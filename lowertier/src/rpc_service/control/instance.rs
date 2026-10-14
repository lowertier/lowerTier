use std::sync::{Arc, Weak};

use crate::{
    common::global_ctx::GlobalCtx, instance::instance::InstanceConfigPatcher,
    peers::peer_manager::PeerManager,
};

#[derive(Clone)]
pub struct ControlInstance {
    pub peer_manager: Weak<PeerManager>,
    pub global_ctx: Weak<GlobalCtx>,
    pub patcher: InstanceConfigPatcher,
}

impl ControlInstance {
    pub fn peers(&self) -> anyhow::Result<Arc<PeerManager>> {
        crate::utils::weak_upgrade(&self.peer_manager)
    }

    pub fn context(&self) -> anyhow::Result<Arc<GlobalCtx>> {
        crate::utils::weak_upgrade(&self.global_ctx)
    }
}
