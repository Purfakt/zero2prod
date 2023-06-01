#[derive(Debug)]
pub struct IdempotencyKey(String);

impl TryFrom<String> for IdempotencyKey {
    type Error = anyhow::Error;

    fn try_from(s: String) -> Result<Self, Self::Error> {
        anyhow::ensure!(!s.is_empty(), "The idempotency key cannot be empty");

        let max_length = 50;
        anyhow::ensure!(
            s.len() < max_length,
            "The idempotency key must be shorter than {max_length} characters"
        );

        Ok(Self(s))
    }
}

impl From<IdempotencyKey> for String {
    fn from(k: IdempotencyKey) -> Self {
        k.0
    }
}

impl AsRef<str> for IdempotencyKey {
    fn as_ref(&self) -> &str {
        &self.0
    }
}
