use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use super::{ControlPrincipalV1, ControlScopeV1, CredentialProfileAccessV1, CredentialProfileIdV1};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthorizationDenied;

impl std::fmt::Display for AuthorizationDenied {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("authorization denied")
    }
}

impl std::error::Error for AuthorizationDenied {}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum InventoryScopeRequestV1 {
    PublicOnly,
    CredentialProfile {
        credential_profile_id: CredentialProfileIdV1,
    },
    AllAuthorized,
}

/// A visibility capability produced only after inventory-read authorization.
///
/// Inventory implementations should require this type before applying query
/// filters, ranking, counts, facets, or pagination. Its fields are private so a
/// deserialized search request cannot bypass this authorization seam.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthorizedInventoryScopeV1 {
    include_public: bool,
    credential_profiles: AuthorizedCredentialProfilesV1,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum AuthorizedCredentialProfilesV1 {
    None,
    Selected(BTreeSet<CredentialProfileIdV1>),
    All,
}

impl AuthorizedInventoryScopeV1 {
    pub fn includes_public(&self) -> bool {
        self.include_public
    }

    pub fn includes_credential_profile(
        &self,
        credential_profile_id: &CredentialProfileIdV1,
    ) -> bool {
        match &self.credential_profiles {
            AuthorizedCredentialProfilesV1::None => false,
            AuthorizedCredentialProfilesV1::Selected(ids) => ids.contains(credential_profile_id),
            AuthorizedCredentialProfilesV1::All => true,
        }
    }

    pub fn selected_credential_profiles(
        &self,
    ) -> Option<impl Iterator<Item = &CredentialProfileIdV1>> {
        match &self.credential_profiles {
            AuthorizedCredentialProfilesV1::Selected(ids) => Some(ids.iter()),
            AuthorizedCredentialProfilesV1::None | AuthorizedCredentialProfilesV1::All => None,
        }
    }

    pub fn includes_all_credential_profiles(&self) -> bool {
        self.credential_profiles == AuthorizedCredentialProfilesV1::All
    }
}

/// A search request paired with its already-authorized visibility capability.
///
/// Keeping the query opaque to this module lets inventory filters evolve while
/// preserving the rule that authorization precedes every observable search
/// operation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthorizedInventoryRequestV1<Query> {
    query: Query,
    scope: AuthorizedInventoryScopeV1,
}

impl<Query> AuthorizedInventoryRequestV1<Query> {
    pub fn query(&self) -> &Query {
        &self.query
    }

    pub fn scope(&self) -> &AuthorizedInventoryScopeV1 {
        &self.scope
    }

    pub fn into_parts(self) -> (Query, AuthorizedInventoryScopeV1) {
        (self.query, self.scope)
    }
}

pub fn authorize_inventory_scope(
    principal: &ControlPrincipalV1,
    requested: &InventoryScopeRequestV1,
) -> Result<AuthorizedInventoryScopeV1, AuthorizationDenied> {
    if principal.validate().is_err() || !principal.allows(ControlScopeV1::InventoryRead) {
        return Err(AuthorizationDenied);
    }

    let repository_access = &principal.grant.repository_access;
    match requested {
        InventoryScopeRequestV1::PublicOnly if repository_access.public => {
            Ok(AuthorizedInventoryScopeV1 {
                include_public: true,
                credential_profiles: AuthorizedCredentialProfilesV1::None,
            })
        }
        InventoryScopeRequestV1::CredentialProfile {
            credential_profile_id,
        } if repository_access
            .credential_profiles
            .allows(credential_profile_id) =>
        {
            Ok(AuthorizedInventoryScopeV1 {
                include_public: false,
                credential_profiles: AuthorizedCredentialProfilesV1::Selected(BTreeSet::from([
                    credential_profile_id.clone(),
                ])),
            })
        }
        InventoryScopeRequestV1::AllAuthorized => {
            let credential_profiles = match &repository_access.credential_profiles {
                CredentialProfileAccessV1::None => AuthorizedCredentialProfilesV1::None,
                CredentialProfileAccessV1::Selected {
                    credential_profile_ids,
                } => AuthorizedCredentialProfilesV1::Selected(credential_profile_ids.clone()),
                CredentialProfileAccessV1::All => AuthorizedCredentialProfilesV1::All,
            };
            Ok(AuthorizedInventoryScopeV1 {
                include_public: repository_access.public,
                credential_profiles,
            })
        }
        InventoryScopeRequestV1::PublicOnly | InventoryScopeRequestV1::CredentialProfile { .. } => {
            Err(AuthorizationDenied)
        }
    }
}

pub fn authorize_inventory_request<Query>(
    principal: &ControlPrincipalV1,
    requested_scope: &InventoryScopeRequestV1,
    query: Query,
) -> Result<AuthorizedInventoryRequestV1<Query>, AuthorizationDenied> {
    Ok(AuthorizedInventoryRequestV1 {
        query,
        scope: authorize_inventory_scope(principal, requested_scope)?,
    })
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::*;
    use crate::control_auth::model::principal_id_for_oidc;
    use crate::control_auth::{
        ControlRoleV1, CredentialProfileAccessV1, PrincipalAuthenticationV1, PrincipalGrantV1,
        RepositoryAccessV1, SCHEMA_VERSION_V1,
    };

    fn reader(access: RepositoryAccessV1) -> ControlPrincipalV1 {
        ControlPrincipalV1 {
            schema_version: SCHEMA_VERSION_V1,
            id: principal_id_for_oidc("https://issuer.example", "reader"),
            authentication: PrincipalAuthenticationV1::Oidc {
                issuer: "https://issuer.example".to_owned(),
                subject: "reader".to_owned(),
            },
            grant: PrincipalGrantV1::for_roles(
                BTreeSet::from([ControlRoleV1::InventoryReader]),
                access,
            )
            .unwrap(),
        }
    }

    #[test]
    fn private_scope_is_resolved_before_the_query_is_exposed() {
        let allowed = CredentialProfileIdV1::parse("installation-42").unwrap();
        let principal = reader(RepositoryAccessV1 {
            public: true,
            credential_profiles: CredentialProfileAccessV1::Selected {
                credential_profile_ids: BTreeSet::from([allowed.clone()]),
            },
        });
        let request = authorize_inventory_request(
            &principal,
            &InventoryScopeRequestV1::CredentialProfile {
                credential_profile_id: allowed.clone(),
            },
            "fs2",
        )
        .unwrap();

        assert_eq!(request.query(), &"fs2");
        assert!(!request.scope().includes_public());
        assert!(request.scope().includes_credential_profile(&allowed));
    }

    #[test]
    fn unauthorized_profile_and_missing_read_scope_are_indistinguishable() {
        let principal = reader(RepositoryAccessV1::public_only());
        let private = InventoryScopeRequestV1::CredentialProfile {
            credential_profile_id: CredentialProfileIdV1::parse("installation-42").unwrap(),
        };

        assert_eq!(
            authorize_inventory_scope(&principal, &private),
            Err(AuthorizationDenied)
        );

        let mut no_read = principal;
        no_read.grant.scopes = BTreeSet::from([ControlScopeV1::JobsRead]);
        assert_eq!(
            authorize_inventory_scope(&no_read, &InventoryScopeRequestV1::PublicOnly),
            Err(AuthorizationDenied)
        );
    }
}
