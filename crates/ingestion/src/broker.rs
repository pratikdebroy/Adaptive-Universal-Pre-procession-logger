use aegislog_engine::{EventQuarantineEntry, OCSFEvent, ParserQuarantineEntry, ProcessingCopy};
use tokio::sync::broadcast;

/// Broker topic channels for the AegisLog streaming pipeline.
#[derive(Clone)]
pub struct PipelineBroker {
    raw_logs_tx: broadcast::Sender<ProcessingCopy>,
    parsed_logs_tx: broadcast::Sender<OCSFEvent>,
    event_quarantine_tx: broadcast::Sender<EventQuarantineEntry>,
    parser_quarantine_tx: broadcast::Sender<ParserQuarantineEntry>,
}

impl Default for PipelineBroker {
    fn default() -> Self {
        Self::new(10000)
    }
}

impl PipelineBroker {
    pub fn new(capacity: usize) -> Self {
        let (raw_logs_tx, _) = broadcast::channel(capacity);
        let (parsed_logs_tx, _) = broadcast::channel(capacity);
        let (event_quarantine_tx, _) = broadcast::channel(capacity);
        let (parser_quarantine_tx, _) = broadcast::channel(capacity);

        Self {
            raw_logs_tx,
            parsed_logs_tx,
            event_quarantine_tx,
            parser_quarantine_tx,
        }
    }

    // Publish methods
    pub fn publish_raw(&self, event: ProcessingCopy) {
        let _ = self.raw_logs_tx.send(event);
    }

    pub fn publish_parsed(&self, event: OCSFEvent) {
        let _ = self.parsed_logs_tx.send(event);
    }

    pub fn publish_event_quarantine(&self, entry: EventQuarantineEntry) {
        let _ = self.event_quarantine_tx.send(entry);
    }

    pub fn publish_parser_quarantine(&self, entry: ParserQuarantineEntry) {
        let _ = self.parser_quarantine_tx.send(entry);
    }

    // Subscription methods
    pub fn subscribe_raw(&self) -> broadcast::Receiver<ProcessingCopy> {
        self.raw_logs_tx.subscribe()
    }

    pub fn subscribe_parsed(&self) -> broadcast::Receiver<OCSFEvent> {
        self.parsed_logs_tx.subscribe()
    }

    pub fn subscribe_event_quarantine(&self) -> broadcast::Receiver<EventQuarantineEntry> {
        self.event_quarantine_tx.subscribe()
    }

    pub fn subscribe_parser_quarantine(&self) -> broadcast::Receiver<ParserQuarantineEntry> {
        self.parser_quarantine_tx.subscribe()
    }
}
