pub(crate) const TUN_SCHEDULER_PACKET_CAPACITY: usize = 128;
pub(crate) const TUN_SCHEDULER_BYTE_CAPACITY: usize = 512 * 1024;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct DrainStats {
    pub(crate) packets: usize,
    pub(crate) bytes: usize,
}
