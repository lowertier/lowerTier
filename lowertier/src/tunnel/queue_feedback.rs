use std::{
    sync::{Arc, Weak},
    time::Duration,
};

/// One NIC flow follows its current transport without retaining the connection.
#[derive(Debug, Default)]
pub(crate) struct FlowQueueFeedback {
    queue: parking_lot::Mutex<(Weak<quinn::DatagramQueueFeedback>, u64)>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn binding_replaces_the_transport_and_does_not_retain_it() {
        let flow = FlowQueueFeedback::default();
        let first = Arc::new(quinn::DatagramQueueFeedback::default());
        flow.bind(&first);
        assert_eq!(Arc::strong_count(&first), 1);
        let second = Arc::new(quinn::DatagramQueueFeedback::default());
        flow.bind(&second);
        assert_eq!(flow.queue.lock().0.as_ptr(), Arc::as_ptr(&second));
        flow.clear();
        assert!(flow.queue.lock().0.upgrade().is_none());
        flow.bind(&second);
        // Emulate an unseen generation after the FIFO has drained.
        flow.queue.lock().1 = second.congestion_events().wrapping_sub(1);
        assert_eq!(flow.snapshot(), (Duration::from_millis(5), true));
        assert_eq!(flow.snapshot(), (Duration::ZERO, false));
        let tagged = Arc::new(FlowQueueFeedback::default());
        tagged.bind(&second);
        let mut packet = super::super::packet_def::ZCPacket::new_with_payload(b"h2");
        packet.queue_feedback = Some(tagged.clone());
        let mut writer = super::super::common::FramedWriter::new(tokio::io::sink());
        futures::Sink::start_send(std::pin::Pin::new(&mut writer), packet).unwrap();
        assert!(tagged.queue.lock().0.upgrade().is_none());
        drop(first);
        assert_eq!(flow.snapshot(), (Duration::ZERO, false));
        drop(second);
        assert!(flow.queue.lock().0.upgrade().is_none());
        assert_eq!(flow.snapshot(), (Duration::ZERO, false));
    }
}

impl FlowQueueFeedback {
    pub(crate) fn clear(&self) {
        *self.queue.lock() = (Weak::new(), 0);
    }

    pub(crate) fn bind(&self, queue: &Arc<quinn::DatagramQueueFeedback>) {
        let mut current = self.queue.lock();
        if current.0.as_ptr() != Arc::as_ptr(queue) {
            *current = (Arc::downgrade(queue), queue.congestion_events());
        }
    }

    pub(crate) fn snapshot(&self) -> (Duration, bool) {
        let mut current = self.queue.lock();
        let Some(queue) = current.0.upgrade() else {
            return (Duration::ZERO, false);
        };
        let generation = queue.congestion_events();
        let (delay, persistent) = queue.snapshot();
        // Flush can drain Quinn before NIC delivery credits resume. Retain one signal per flow.
        let unseen = generation != current.1;
        current.1 = generation;
        (
            if unseen {
                delay.max(Duration::from_millis(5))
            } else {
                delay
            },
            persistent || unseen,
        )
    }
}
