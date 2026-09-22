// Inner TCP controls each flow; QUIC controls aggregate tunnel bursts. Use
// loss-responsive CUBIC so a constrained path can reduce its offered load
// promptly, limiting repeated inner-TCP recovery and DATAGRAM fragmentation.
// Keep the standard bounded initial window and adaptive, paced growth.
pub use quinn_proto::congestion::CubicConfig as TunnelConfig;
