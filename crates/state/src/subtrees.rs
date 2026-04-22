//! Top-level subtree tags. Every key in the authenticated store is scoped by one.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Subtree {
    Accounts,
    Code,
    Storage,
    Meta,
    Reflect,
    Blocks,
    Headers,
    Witnesses,
}

impl Subtree {
    pub fn tag(self) -> &'static [u8] {
        match self {
            Self::Accounts => b"accounts",
            Self::Code => b"code",
            Self::Storage => b"storage",
            Self::Meta => b"meta",
            Self::Reflect => b"reflect",
            Self::Blocks => b"blocks",
            Self::Headers => b"headers",
            Self::Witnesses => b"witnesses",
        }
    }
}
