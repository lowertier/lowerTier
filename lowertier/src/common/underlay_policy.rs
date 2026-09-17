use std::{collections::BTreeSet, net::IpAddr, str::FromStr};

use anyhow::{Context, Result};
use cidr::IpCidr;

/// Deny rules for LowTier's local underlay interfaces and IP paths.
///
/// CIDR rules apply symmetrically to local source addresses and remote
/// destinations. Interface names are exact matches so platform naming remains
/// explicit and predictable.
#[derive(Clone, Debug, Default)]
pub struct UnderlayPolicy {
    denied_interfaces: BTreeSet<String>,
    denied_cidrs: Vec<IpCidr>,
}

impl UnderlayPolicy {
    pub fn new(denied_interfaces: &[String], denied_cidrs: &[String]) -> Result<Self> {
        let denied_interfaces = denied_interfaces.iter().cloned().collect();
        let denied_cidrs = denied_cidrs
            .iter()
            .map(|rule| {
                IpCidr::from_str(rule)
                    .with_context(|| format!("invalid underlay deny CIDR: {rule}"))
            })
            .collect::<Result<Vec<_>>>()?;

        Ok(Self {
            denied_interfaces,
            denied_cidrs,
        })
    }

    pub fn is_active(&self) -> bool {
        !self.denied_interfaces.is_empty() || !self.denied_cidrs.is_empty()
    }

    pub fn allows_interface(&self, name: &str) -> bool {
        self.denied_interface_rule(name).is_none()
    }

    pub fn denied_interface_rule(&self, name: &str) -> Option<&str> {
        self.denied_interfaces.get(name).map(String::as_str)
    }

    pub fn has_interface_rules(&self) -> bool {
        !self.denied_interfaces.is_empty()
    }

    pub fn allows_ip(&self, addr: IpAddr) -> bool {
        self.denied_ip_rule(addr).is_none()
    }

    pub fn denied_ip_rule(&self, addr: IpAddr) -> Option<&IpCidr> {
        self.denied_cidrs.iter().find(|cidr| match (cidr, addr) {
            (IpCidr::V4(cidr), IpAddr::V4(addr)) => cidr.contains(&addr),
            (IpCidr::V6(cidr), IpAddr::V6(addr)) => cidr.contains(&addr),
            _ => false,
        })
    }

    pub fn allows_local_endpoint(&self, interface: Option<&str>, addr: IpAddr) -> bool {
        let interface_allowed = interface
            .map(|name| self.allows_interface(name))
            .unwrap_or_else(|| !self.has_interface_rules());
        interface_allowed && self.allows_ip(addr)
    }

    pub fn allows_remote(&self, addr: IpAddr) -> bool {
        self.allows_ip(addr)
    }
}

#[cfg(test)]
mod tests {
    use super::UnderlayPolicy;
    use std::net::IpAddr;

    fn ip(value: &str) -> IpAddr {
        value.parse().unwrap()
    }
}
