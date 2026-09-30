use std::sync::Arc;

use crate::broker::RedisBroker;
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use connections::Hub;
use domain::UserId;
use domain::messaging::{Message, MessageEvent, MessageNotifier};

use super::events::{DmDeliveryFailedPayload, DmPayload, EditedDmPayload, WsAttachment, WsEvent};

/// Pushes message events to an account's live sessions; the durable ones also go to its event
/// stream, which a client replays on reconnect.
pub struct HubMessageNotifier {
    hub: Arc<Hub>,
    broker: Arc<RedisBroker>,
}

impl HubMessageNotifier {
    pub fn new(hub: Arc<Hub>, broker: Arc<RedisBroker>) -> Self {
        Self { hub, broker }
    }

    fn live(&self, to: UserId, event: WsEvent) {
        super::push(&self.hub, &to.as_uuid(), event);
    }

    fn durable(&self, to: UserId, event: WsEvent) {
        let frame = super::frame(&event);
        let (broker, stored) = (Arc::clone(&self.broker), frame.to_string());
        tokio::spawn(async move {
            if let Err(e) = broker.publish(to.as_uuid(), &stored).await {
                tracing::warn!(user_id = %to, "broker publish failed: {e}");
            }
        });
        self.hub.send_to_user(&to.as_uuid(), frame);
    }
}

fn new_dm(event: &MessageEvent) -> WsEvent {
    let m = &event.message;
    WsEvent::NewDm(DmPayload {
        message_id: m.id.as_uuid(),
        conversation_id: m.conversation.as_uuid(),
        kind: event.kind.as_str().to_owned(),
        sender_address: event.sender_address.clone(),
        sender_display_name: event.sender_display_name.clone(),
        mls_ciphertext: B64.encode(m.ciphertext.as_bytes()),
        created_at: m.created_at,
        reply_to_id: m.reply_to.map(|id| id.as_uuid()),
        attachments: m
            .attachments
            .iter()
            .map(|a| WsAttachment {
                id: a.id.as_uuid(),
                mime_type: a.mime_type.clone(),
                byte_size: a.byte_size,
                original_filename: a.original_filename.clone(),
            })
            .collect(),
        client_id: event.client_id.clone(),
    })
}

fn edited(message: &Message) -> Option<WsEvent> {
    Some(WsEvent::MessageEdited(EditedDmPayload {
        message_id: message.id.as_uuid(),
        new_mls_ciphertext: B64.encode(message.ciphertext.as_bytes()),
        edited_at: message.edited_at?,
    }))
}

impl MessageNotifier for HubMessageNotifier {
    fn message(&self, to: UserId, event: &MessageEvent) {
        self.durable(to, new_dm(event));
    }

    fn echo(&self, to: UserId, event: &MessageEvent) {
        self.live(to, new_dm(event));
    }

    fn edited(&self, to: UserId, message: &Message) {
        if let Some(event) = edited(message) {
            self.durable(to, event);
        }
    }

    fn edit_echoed(&self, to: UserId, message: &Message) {
        if let Some(event) = edited(message) {
            self.live(to, event);
        }
    }

    fn delivery_failed(&self, to: UserId, message: &Message) {
        self.live(
            to,
            WsEvent::DmDeliveryFailed(DmDeliveryFailedPayload {
                message_id: message.id.as_uuid(),
                conversation_id: message.conversation.as_uuid(),
            }),
        );
    }
}
