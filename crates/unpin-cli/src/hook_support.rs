use std::path::Path;

use unpin_core::{
    catalog::Catalog,
    discovery::{DiscoveryItem, DiscoveryOutput},
    profiles::ProfileStore,
};

pub(crate) fn require_profile_membership(
    app_state_root: &Path,
    discovery: &DiscoveryOutput,
    hook: &DiscoveryItem,
    profile_digest: &str,
) -> Result<(), String> {
    let revision = ProfileStore::new(app_state_root)
        .load_revision(profile_digest)
        .map_err(|error| error.to_string())?
        .ok_or_else(|| "compiled profile revision is missing".to_string())?;
    let catalog = Catalog::from_discovery(discovery).map_err(|error| error.to_string())?;
    let capability = catalog
        .find_provider_view(hook.provider, &hook.id)
        .ok_or_else(|| "hook capability is missing from catalog".to_string())?;
    if revision.selects(&capability.id, hook.provider) {
        Ok(())
    } else {
        Err("hook is not selected by compiled profile".to_string())
    }
}
