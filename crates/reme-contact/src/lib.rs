#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]

use reme_identity::{PublicID, RoutingKey};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[repr(u8)]
pub enum TrustLevel {
    Stranger = 0,
    Known = 1,
    Verified = 2,
    Trusted = 3,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Contact {
    pub id: i64,
    pub public_id: PublicID,
    pub routing_key: RoutingKey,
    pub name: Option<String>,
    pub trust_level: TrustLevel,
    pub verified_at: Option<i64>,
    pub created_at: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AddContactOutcome {
    Created(Contact),
    Promoted(Contact),
    AlreadyPresent(Contact),
}

#[cfg(test)]
mod tests {
    use super::{AddContactOutcome, Contact, TrustLevel};
    use reme_identity::Identity;

    #[test]
    fn trust_level_orders_from_stranger_to_trusted() {
        assert!(TrustLevel::Stranger < TrustLevel::Known);
        assert!(TrustLevel::Known < TrustLevel::Verified);
        assert!(TrustLevel::Verified < TrustLevel::Trusted);
    }

    #[test]
    fn add_contact_outcome_carries_contact_payload() {
        let identity = Identity::generate();
        let public_id = *identity.public_id();
        let contact = Contact {
            id: 7,
            public_id,
            routing_key: public_id.routing_key(),
            name: Some("Alice".to_string()),
            trust_level: TrustLevel::Verified,
            verified_at: Some(1_234),
            created_at: 567,
        };

        assert_eq!(
            AddContactOutcome::Created(contact.clone()),
            AddContactOutcome::Created(contact.clone())
        );
        assert_eq!(
            AddContactOutcome::Promoted(contact.clone()),
            AddContactOutcome::Promoted(contact.clone())
        );
        assert_eq!(
            AddContactOutcome::AlreadyPresent(contact.clone()),
            AddContactOutcome::AlreadyPresent(contact)
        );
    }
}
