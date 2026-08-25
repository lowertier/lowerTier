use std::{
    collections::{HashMap, hash_map::DefaultHasher},
    hash::{Hash, Hasher},
    net::IpAddr,
    sync::{Arc, RwLock},
    time::{Duration, Instant},
};

use arc_swap::ArcSwap;
use cidr::{IpCidr, Ipv4Cidr, Ipv6Cidr};
use dashmap::{DashMap, mapref::entry::Entry};
use prefix_trie::PrefixMap;

use crate::common::PeerId;

#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
pub enum RouteSource {
    Static,
    Bgp,
    Overlay,
}

#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
pub enum ServiceRouteAction {
    Forward,
    ExitSnat,
    Blackhole,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub struct ServiceRoute {
    pub prefix: IpCidr,
    pub gateway: PeerId,
    pub preference: u32,
    pub metric: u32,
    pub path_id: u64,
    pub action: ServiceRouteAction,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ServiceRouteSelection {
    pub prefix: IpCidr,
    pub gateway: PeerId,
    pub path_id: u64,
    pub action: ServiceRouteAction,
}

#[derive(Debug, Default)]
pub struct ServiceRouteSnapshot {
    generation: u64,
    routes: Arc<[ServiceRoute]>,
    ipv4: PrefixMap<Ipv4Cidr, Arc<[ServiceRoute]>>,
    ipv6: PrefixMap<Ipv6Cidr, Arc<[ServiceRoute]>>,
}

impl ServiceRouteSnapshot {
    pub fn from_routes(generation: u64, routes: Vec<ServiceRoute>) -> Self {
        let mut grouped = HashMap::<IpCidr, Vec<ServiceRoute>>::new();
        for route in &routes {
            grouped.entry(route.prefix).or_default().push(route.clone());
        }
        let mut snapshot = Self {
            generation,
            routes: Arc::from(routes),
            ..Default::default()
        };
        for (prefix, mut candidates) in grouped {
            candidates.sort_unstable_by(|left, right| {
                right
                    .preference
                    .cmp(&left.preference)
                    .then_with(|| left.metric.cmp(&right.metric))
                    .then_with(|| left.gateway.cmp(&right.gateway))
                    .then_with(|| left.path_id.cmp(&right.path_id))
            });
            let candidates = Arc::<[ServiceRoute]>::from(candidates);
            match prefix {
                IpCidr::V4(prefix) => {
                    snapshot.ipv4.insert(prefix, candidates);
                }
                IpCidr::V6(prefix) => {
                    snapshot.ipv6.insert(prefix, candidates);
                }
            }
        }
        snapshot
    }

    pub fn generation(&self) -> u64 {
        self.generation
    }

    pub fn candidates(&self, address: IpAddr) -> Option<&[ServiceRoute]> {
        match address {
            IpAddr::V4(address) => self
                .ipv4
                .get_lpm(&Ipv4Cidr::new(address, 32).ok()?)
                .map(|entry| entry.1.as_ref()),
            IpAddr::V6(address) => self
                .ipv6
                .get_lpm(&Ipv6Cidr::new(address, 128).ok()?)
                .map(|entry| entry.1.as_ref()),
        }
    }

    pub fn routes(&self) -> &[ServiceRoute] {
        &self.routes
    }
}

#[derive(Clone, Debug, Hash, PartialEq, Eq)]
struct GatewayFlowKey {
    prefix: IpCidr,
    flow: u64,
}

#[derive(Clone)]
struct GatewayPin {
    selection: ServiceRouteSelection,
    created_at: Instant,
}

#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
struct GatewayFlowPlanKey {
    address: IpAddr,
    flow: u64,
}

#[derive(Clone)]
struct GatewayFlowPlan {
    generation: u64,
    selection: ServiceRouteSelection,
    created_at: Instant,
}

pub struct ServiceRouteStore {
    routes: RwLock<HashMap<RouteSource, Vec<ServiceRoute>>>,
    snapshot: ArcSwap<ServiceRouteSnapshot>,
    pins: DashMap<GatewayFlowKey, GatewayPin>,
    plans: DashMap<GatewayFlowPlanKey, GatewayFlowPlan>,
    pin_capacity: usize,
    pin_ttl: Duration,
    #[cfg(test)]
    selection_count: std::sync::atomic::AtomicUsize,
}

impl ServiceRouteStore {
    pub fn new(pin_capacity: usize, pin_ttl: Duration) -> Self {
        assert!(pin_capacity > 0);
        Self {
            routes: RwLock::new(HashMap::new()),
            snapshot: ArcSwap::from_pointee(ServiceRouteSnapshot::default()),
            pins: DashMap::with_capacity(pin_capacity.min(1024)),
            plans: DashMap::with_capacity(pin_capacity.min(1024)),
            pin_capacity,
            pin_ttl,
            #[cfg(test)]
            selection_count: std::sync::atomic::AtomicUsize::new(0),
        }
    }

    #[cfg(test)]
    pub(crate) fn selection_count(&self) -> usize {
        self.selection_count
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    #[cfg(test)]
    pub(crate) fn reset_selection_count(&self) {
        self.selection_count
            .store(0, std::sync::atomic::Ordering::Relaxed);
    }

    pub fn snapshot(&self) -> Arc<ServiceRouteSnapshot> {
        self.snapshot.load_full()
    }

    pub fn replace_source(&self, source: RouteSource, mut routes: Vec<ServiceRoute>) {
        routes.sort_unstable_by(|left, right| {
            left.prefix
                .cmp(&right.prefix)
                .then_with(|| left.gateway.cmp(&right.gateway))
                .then_with(|| left.path_id.cmp(&right.path_id))
        });
        routes.dedup_by(|left, right| {
            left.prefix == right.prefix
                && left.gateway == right.gateway
                && left.path_id == right.path_id
        });
        let mut table = self
            .routes
            .write()
            .expect("service route table was poisoned");
        table.insert(source, routes);
        let generation = self.snapshot.load().generation.wrapping_add(1).max(1);
        self.snapshot
            .store(Arc::new(Self::build_snapshot(&table, generation)));
    }

    pub fn routes_from(&self, source: RouteSource) -> Vec<ServiceRoute> {
        self.routes
            .read()
            .expect("service route table was poisoned")
            .get(&source)
            .cloned()
            .unwrap_or_default()
    }

    pub fn select_gateway<F>(
        &self,
        address: IpAddr,
        flow: u64,
        gateway_is_live: F,
    ) -> Option<ServiceRouteSelection>
    where
        F: Fn(PeerId) -> bool,
    {
        #[cfg(test)]
        self.selection_count
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let snapshot = self.snapshot.load_full();
        let plan_key = GatewayFlowPlanKey { address, flow };
        let now = Instant::now();
        if let Entry::Occupied(plan) = self.plans.entry(plan_key) {
            let current = plan.get();
            let plan_is_live = current.selection.action == ServiceRouteAction::Blackhole
                || gateway_is_live(current.selection.gateway);
            if current.generation == snapshot.generation()
                && now.duration_since(current.created_at) <= self.pin_ttl
                && plan_is_live
            {
                return Some(current.selection.clone());
            }
            plan.remove();
        }
        let candidates = snapshot.candidates(address)?;
        let route_is_live = |route: &ServiceRoute| {
            route.action == ServiceRouteAction::Blackhole || gateway_is_live(route.gateway)
        };
        let best_preference = candidates
            .iter()
            .filter(|route| route_is_live(route))
            .map(|route| route.preference)
            .max()?;
        let best_metric = candidates
            .iter()
            .filter(|route| route.preference == best_preference && route_is_live(route))
            .map(|route| route.metric)
            .min()?;
        let eligible = candidates
            .iter()
            .filter(|route| {
                route.preference == best_preference
                    && route.metric == best_metric
                    && route_is_live(route)
            })
            .collect::<Vec<_>>();
        let prefix = eligible.first()?.prefix;
        let key = GatewayFlowKey { prefix, flow };
        if let Entry::Occupied(pin) = self.pins.entry(key.clone()) {
            let current = &pin.get().selection;
            if now.duration_since(pin.get().created_at) <= self.pin_ttl
                && eligible.iter().any(|route| {
                    route.gateway == current.gateway
                        && route.path_id == current.path_id
                        && route.action == current.action
                })
            {
                let selection = current.clone();
                drop(pin);
                self.reserve_plan_capacity(now);
                self.plans.insert(
                    plan_key,
                    GatewayFlowPlan {
                        generation: snapshot.generation(),
                        selection: selection.clone(),
                        created_at: now,
                    },
                );
                return Some(selection);
            }
            pin.remove();
        }

        let route = eligible.into_iter().max_by_key(|route| {
            let mut hasher = DefaultHasher::new();
            flow.hash(&mut hasher);
            route.gateway.hash(&mut hasher);
            route.path_id.hash(&mut hasher);
            hasher.finish()
        })?;
        let selection = ServiceRouteSelection {
            prefix: route.prefix,
            gateway: route.gateway,
            path_id: route.path_id,
            action: route.action,
        };
        self.reserve_pin_capacity(now);
        self.pins.insert(
            key,
            GatewayPin {
                selection: selection.clone(),
                created_at: now,
            },
        );
        self.reserve_plan_capacity(now);
        self.plans.insert(
            plan_key,
            GatewayFlowPlan {
                generation: snapshot.generation(),
                selection: selection.clone(),
                created_at: now,
            },
        );
        Some(selection)
    }

    fn build_snapshot(
        routes: &HashMap<RouteSource, Vec<ServiceRoute>>,
        generation: u64,
    ) -> ServiceRouteSnapshot {
        ServiceRouteSnapshot::from_routes(generation, routes.values().flatten().cloned().collect())
    }

    fn reserve_pin_capacity(&self, now: Instant) {
        if self.pins.len() < self.pin_capacity {
            return;
        }
        self.pins
            .retain(|_, pin| now.duration_since(pin.created_at) <= self.pin_ttl);
        if self.pins.len() < self.pin_capacity {
            return;
        }
        let remove_count = self.pins.len() - self.pin_capacity.saturating_mul(3) / 4;
        let keys = self
            .pins
            .iter()
            .take(remove_count.max(1))
            .map(|entry| entry.key().clone())
            .collect::<Vec<_>>();
        for key in keys {
            self.pins.remove(&key);
        }
    }

    fn reserve_plan_capacity(&self, now: Instant) {
        if self.plans.len() < self.pin_capacity {
            return;
        }
        let generation = self.snapshot.load().generation();
        self.plans.retain(|_, plan| {
            now.duration_since(plan.created_at) <= self.pin_ttl && plan.generation == generation
        });
        if self.plans.len() < self.pin_capacity {
            return;
        }
        let remove_count = self.plans.len() - self.pin_capacity.saturating_mul(3) / 4;
        let keys = self
            .plans
            .iter()
            .take(remove_count.max(1))
            .map(|entry| *entry.key())
            .collect::<Vec<_>>();
        for key in keys {
            self.plans.remove(&key);
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{cell::Cell, collections::HashSet, net::IpAddr, time::Duration};

    use cidr::IpCidr;

    use super::{RouteSource, ServiceRoute, ServiceRouteAction, ServiceRouteStore};

    fn route(prefix: &str, gateway: u32, preference: u32, metric: u32) -> ServiceRoute {
        ServiceRoute {
            prefix: prefix.parse::<IpCidr>().unwrap(),
            gateway,
            preference,
            metric,
            path_id: gateway as u64,
            action: ServiceRouteAction::Forward,
        }
    }

    #[test]
    fn selection_uses_longest_prefix_before_route_rank() {
        let store = ServiceRouteStore::new(128, Duration::from_secs(300));
        store.replace_source(
            RouteSource::Bgp,
            vec![
                route("10.0.0.0/8", 10, 200, 0),
                route("10.1.0.0/16", 20, 100, 100),
            ],
        );

        let selected = store
            .select_gateway("10.1.2.3".parse::<IpAddr>().unwrap(), 7, |_| true)
            .unwrap();

        assert_eq!(selected.gateway, 20);
        assert_eq!(selected.prefix.to_string(), "10.1.0.0/16");
    }

    #[test]
    fn equal_routes_use_multiple_gateways_and_pin_each_flow() {
        let store = ServiceRouteStore::new(128, Duration::from_secs(300));
        store.replace_source(
            RouteSource::Bgp,
            vec![
                route("192.0.2.0/24", 10, 100, 20),
                route("192.0.2.0/24", 20, 100, 20),
            ],
        );
        let destination = "192.0.2.8".parse::<IpAddr>().unwrap();
        let gateways = (0..256)
            .map(|flow| {
                let first = store.select_gateway(destination, flow, |_| true).unwrap();
                let second = store.select_gateway(destination, flow, |_| true).unwrap();
                assert_eq!(first, second);
                first.gateway
            })
            .collect::<HashSet<_>>();

        assert_eq!(gateways, HashSet::from([10, 20]));
    }

    #[test]
    fn unchanged_generation_reuses_the_compiled_flow_plan() {
        let store = ServiceRouteStore::new(128, Duration::from_secs(300));
        store.replace_source(
            RouteSource::Bgp,
            vec![
                route("192.0.2.0/24", 10, 100, 20),
                route("192.0.2.0/24", 20, 100, 20),
            ],
        );
        let destination = "192.0.2.8".parse::<IpAddr>().unwrap();
        let calls = Cell::new(0);
        store
            .select_gateway(destination, 7, |_| {
                calls.set(calls.get() + 1);
                true
            })
            .unwrap();
        calls.set(0);

        store
            .select_gateway(destination, 7, |_| {
                calls.set(calls.get() + 1);
                true
            })
            .unwrap();

        assert_eq!(calls.get(), 1);
    }

    #[test]
    fn withdrawn_gateway_moves_only_its_pinned_flows() {
        let store = ServiceRouteStore::new(128, Duration::from_secs(300));
        store.replace_source(
            RouteSource::Bgp,
            vec![
                route("203.0.113.0/24", 10, 100, 20),
                route("203.0.113.0/24", 20, 100, 20),
            ],
        );
        let destination = "203.0.113.7".parse::<IpAddr>().unwrap();
        let flow = (0..1024)
            .find(|flow| {
                store
                    .select_gateway(destination, *flow, |_| true)
                    .is_some_and(|route| route.gateway == 20)
            })
            .unwrap();

        store.replace_source(RouteSource::Bgp, vec![route("203.0.113.0/24", 10, 100, 20)]);

        assert_eq!(
            store
                .select_gateway(destination, flow, |_| true)
                .unwrap()
                .gateway,
            10
        );
    }

    #[test]
    fn blackhole_route_does_not_require_a_gateway() {
        let store = ServiceRouteStore::new(128, Duration::from_secs(300));
        let mut blackhole = route("198.51.100.0/24", 0, 100, 0);
        blackhole.action = ServiceRouteAction::Blackhole;
        store.replace_source(RouteSource::Bgp, vec![blackhole]);

        let selected = store
            .select_gateway("198.51.100.8".parse::<IpAddr>().unwrap(), 1, |_| false)
            .unwrap();

        assert_eq!(selected.action, ServiceRouteAction::Blackhole);
    }
}
