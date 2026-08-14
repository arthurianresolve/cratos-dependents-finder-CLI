use std::collections::BTreeSet;

use serde::{Deserialize, Deserializer, Serialize, de::Error as _};
use sha2::{Digest as _, Sha256};

pub const SCHEMA_VERSION_V1: u16 = 1;
const OIDC_PRINCIPAL_DOMAIN: &[u8] = b"crate-dependent-repos/oidc-principal/v1\0";

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AuthModelError {
    UnsupportedSchemaVersion(u16),
    InvalidPrincipalId,
    InvalidCredentialProfileId,
    MissingRole,
    MissingScope,
    ScopeNotGrantedByRole,
    EmptyRepositoryAccess,
    EmptyCredentialProfileSelection,
    AuthenticationSubjectMismatch,
}

impl std::fmt::Display for AuthModelError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnsupportedSchemaVersion(version) => {
                write!(
                    formatter,
                    "unsupported control-auth schema version {version}"
                )
            }
            Self::InvalidPrincipalId => formatter.write_str("principal ID is invalid"),
            Self::InvalidCredentialProfileId => {
                formatter.write_str("credential profile ID is invalid")
            }
            Self::MissingRole => formatter.write_str("at least one role is required"),
            Self::MissingScope => formatter.write_str("at least one control scope is required"),
            Self::ScopeNotGrantedByRole => {
                formatter.write_str("a control scope is not granted by the principal roles")
            }
            Self::EmptyRepositoryAccess => {
                formatter.write_str("repository access must grant at least one visibility")
            }
            Self::EmptyCredentialProfileSelection => {
                formatter.write_str("selected credential profile access must not be empty")
            }
            Self::AuthenticationSubjectMismatch => {
                formatter.write_str("principal ID does not match its authentication subject")
            }
        }
    }
}

impl std::error::Error for AuthModelError {}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct PrincipalIdV1(String);

impl PrincipalIdV1 {
    pub fn parse(value: impl Into<String>) -> Result<Self, AuthModelError> {
        let value = value.into();
        if !valid_identifier(&value, 192) {
            return Err(AuthModelError::InvalidPrincipalId);
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl<'de> Deserialize<'de> for PrincipalIdV1 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Self::parse(String::deserialize(deserializer)?).map_err(D::Error::custom)
    }
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct CredentialProfileIdV1(String);

impl CredentialProfileIdV1 {
    pub fn parse(value: impl Into<String>) -> Result<Self, AuthModelError> {
        let value = value.into();
        if !valid_identifier(&value, 128) {
            return Err(AuthModelError::InvalidCredentialProfileId);
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl<'de> Deserialize<'de> for CredentialProfileIdV1 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Self::parse(String::deserialize(deserializer)?).map_err(D::Error::custom)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ControlRoleV1 {
    Admin,
    ScanOperator,
    InventoryReader,
    Auditor,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ControlScopeV1 {
    SchedulesRead,
    SchedulesWrite,
    JobsRead,
    JobsSubmit,
    JobsControl,
    InventoryRead,
    AuditRead,
    CredentialProfilesManage,
    ServiceTokensManage,
    SystemManage,
}

impl ControlRoleV1 {
    pub fn grants(self, scope: ControlScopeV1) -> bool {
        match self {
            Self::Admin => true,
            Self::ScanOperator => matches!(
                scope,
                ControlScopeV1::SchedulesRead
                    | ControlScopeV1::SchedulesWrite
                    | ControlScopeV1::JobsRead
                    | ControlScopeV1::JobsSubmit
                    | ControlScopeV1::JobsControl
                    | ControlScopeV1::InventoryRead
            ),
            Self::InventoryReader => scope == ControlScopeV1::InventoryRead,
            Self::Auditor => matches!(
                scope,
                ControlScopeV1::SchedulesRead
                    | ControlScopeV1::JobsRead
                    | ControlScopeV1::InventoryRead
                    | ControlScopeV1::AuditRead
            ),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum CredentialProfileAccessV1 {
    None,
    Selected {
        credential_profile_ids: BTreeSet<CredentialProfileIdV1>,
    },
    All,
}

impl CredentialProfileAccessV1 {
    pub fn allows(&self, credential_profile_id: &CredentialProfileIdV1) -> bool {
        match self {
            Self::None => false,
            Self::Selected {
                credential_profile_ids,
            } => credential_profile_ids.contains(credential_profile_id),
            Self::All => true,
        }
    }

    pub fn validate(&self) -> Result<(), AuthModelError> {
        if matches!(
            self,
            Self::Selected {
                credential_profile_ids
            } if credential_profile_ids.is_empty()
        ) {
            return Err(AuthModelError::EmptyCredentialProfileSelection);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RepositoryAccessV1 {
    pub public: bool,
    pub credential_profiles: CredentialProfileAccessV1,
}

impl RepositoryAccessV1 {
    pub fn public_only() -> Self {
        Self {
            public: true,
            credential_profiles: CredentialProfileAccessV1::None,
        }
    }

    pub fn validate(&self) -> Result<(), AuthModelError> {
        self.credential_profiles.validate()?;
        if !self.public && self.credential_profiles == CredentialProfileAccessV1::None {
            return Err(AuthModelError::EmptyRepositoryAccess);
        }
        Ok(())
    }
}

impl Default for RepositoryAccessV1 {
    fn default() -> Self {
        Self::public_only()
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PrincipalGrantV1 {
    pub roles: BTreeSet<ControlRoleV1>,
    pub scopes: BTreeSet<ControlScopeV1>,
    pub repository_access: RepositoryAccessV1,
}

impl PrincipalGrantV1 {
    pub fn for_roles(
        roles: BTreeSet<ControlRoleV1>,
        repository_access: RepositoryAccessV1,
    ) -> Result<Self, AuthModelError> {
        let scopes = all_control_scopes()
            .filter(|scope| roles.iter().any(|role| role.grants(*scope)))
            .collect();
        let grant = Self {
            roles,
            scopes,
            repository_access,
        };
        grant.validate()?;
        Ok(grant)
    }

    pub fn validate(&self) -> Result<(), AuthModelError> {
        if self.roles.is_empty() {
            return Err(AuthModelError::MissingRole);
        }
        if self.scopes.is_empty() {
            return Err(AuthModelError::MissingScope);
        }
        if self
            .scopes
            .iter()
            .any(|scope| !self.roles.iter().any(|role| role.grants(*scope)))
        {
            return Err(AuthModelError::ScopeNotGrantedByRole);
        }
        self.repository_access.validate()
    }

    pub fn allows(&self, scope: ControlScopeV1) -> bool {
        self.scopes.contains(&scope) && self.roles.iter().any(|role| role.grants(scope))
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum PrincipalAuthenticationV1 {
    Oidc { issuer: String, subject: String },
    ServiceToken { token_id: String },
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ControlPrincipalV1 {
    pub schema_version: u16,
    pub id: PrincipalIdV1,
    pub authentication: PrincipalAuthenticationV1,
    pub grant: PrincipalGrantV1,
}

impl ControlPrincipalV1 {
    pub fn validate(&self) -> Result<(), AuthModelError> {
        if self.schema_version != SCHEMA_VERSION_V1 {
            return Err(AuthModelError::UnsupportedSchemaVersion(
                self.schema_version,
            ));
        }
        self.grant.validate()?;
        match &self.authentication {
            PrincipalAuthenticationV1::Oidc { issuer, subject } => {
                if issuer.trim().is_empty()
                    || subject.trim().is_empty()
                    || self.id != principal_id_for_oidc(issuer, subject)
                {
                    return Err(AuthModelError::AuthenticationSubjectMismatch);
                }
            }
            PrincipalAuthenticationV1::ServiceToken { token_id } => {
                if token_id.trim().is_empty()
                    || principal_id_for_service_token(token_id).as_ref() != Some(&self.id)
                {
                    return Err(AuthModelError::AuthenticationSubjectMismatch);
                }
            }
        }
        Ok(())
    }

    pub fn allows(&self, scope: ControlScopeV1) -> bool {
        self.grant.allows(scope)
    }
}

pub(super) fn principal_id_for_oidc(issuer: &str, subject: &str) -> PrincipalIdV1 {
    let mut hasher = Sha256::new();
    hasher.update(OIDC_PRINCIPAL_DOMAIN);
    hasher.update((issuer.len() as u64).to_be_bytes());
    hasher.update(issuer.as_bytes());
    hasher.update((subject.len() as u64).to_be_bytes());
    hasher.update(subject.as_bytes());
    PrincipalIdV1::parse(format!("oidc:{}", encode_hex(&hasher.finalize())))
        .expect("derived OIDC principal IDs are normalized")
}

pub(super) fn principal_id_for_service_token(token_id: &str) -> Option<PrincipalIdV1> {
    PrincipalIdV1::parse(format!("service_token:{token_id}")).ok()
}

fn all_control_scopes() -> impl Iterator<Item = ControlScopeV1> {
    [
        ControlScopeV1::SchedulesRead,
        ControlScopeV1::SchedulesWrite,
        ControlScopeV1::JobsRead,
        ControlScopeV1::JobsSubmit,
        ControlScopeV1::JobsControl,
        ControlScopeV1::InventoryRead,
        ControlScopeV1::AuditRead,
        ControlScopeV1::CredentialProfilesManage,
        ControlScopeV1::ServiceTokensManage,
        ControlScopeV1::SystemManage,
    ]
    .into_iter()
}

fn valid_identifier(value: &str, max_len: usize) -> bool {
    !value.is_empty()
        && value.len() <= max_len
        && value.trim() == value
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b':' | b'.'))
}

fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(HEX[(byte >> 4) as usize] as char);
        encoded.push(HEX[(byte & 0x0f) as usize] as char);
    }
    encoded
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn service_roles_cannot_be_smuggled_through_deserialization() {
        let result = serde_json::from_str::<ControlRoleV1>(r#""worker""#);
        assert!(result.is_err());
    }

    #[test]
    fn explicit_scopes_can_only_attenuate_roles() {
        let grant = PrincipalGrantV1 {
            roles: BTreeSet::from([ControlRoleV1::InventoryReader]),
            scopes: BTreeSet::from([ControlScopeV1::JobsControl]),
            repository_access: RepositoryAccessV1::public_only(),
        };

        assert_eq!(grant.validate(), Err(AuthModelError::ScopeNotGrantedByRole));
    }

    #[test]
    fn role_defaults_are_explicitly_materialized() {
        let grant = PrincipalGrantV1::for_roles(
            BTreeSet::from([ControlRoleV1::Auditor]),
            RepositoryAccessV1::public_only(),
        )
        .unwrap();

        assert!(grant.allows(ControlScopeV1::AuditRead));
        assert!(grant.allows(ControlScopeV1::InventoryRead));
        assert!(!grant.allows(ControlScopeV1::JobsSubmit));
    }
}
