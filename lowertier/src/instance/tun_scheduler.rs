use std::{array, collections::VecDeque};

use crate::peers::flow::FLOW_SHARD_COUNT as FLOW_SHARD_COUNT_U16;

pub(crate) const TUN_SCHEDULER_PACKET_CAPACITY: usize = 128;
pub(crate) const TUN_SCHEDULER_BYTE_CAPACITY: usize = 512 * 1024;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct DrainStats {
    pub(crate) packets: usize,
    pub(crate) bytes: usize,
}
