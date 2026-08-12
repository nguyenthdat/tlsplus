use std::collections::HashMap;
use std::sync::{Arc, LazyLock, Mutex};
use std::time::Duration;

pub(crate) type WreqClient = wreq::Client;

const PASS_THROUGH_PROFILE: &str = "pass-through";
const FALLBACK_PROFILE: &str = "rustls_default";
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const POOL_IDLE_TIMEOUT: Duration = Duration::from_secs(90);
const MAX_IDLE_PER_HOST: usize = 32;

static CLIENT_CACHE: LazyLock<Mutex<HashMap<String, Arc<WreqClient>>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

fn build_wreq_client(profile_name: &str) -> Result<Arc<WreqClient>, String> {
    let mut builder = wreq::Client::builder();

    if let Some(emulation) = crate::profiles::wreq_emulation(profile_name) {
        builder = builder.emulation(emulation);
    }

    builder
        .no_proxy()
        .connect_timeout(CONNECT_TIMEOUT)
        .pool_idle_timeout(POOL_IDLE_TIMEOUT)
        .pool_max_idle_per_host(MAX_IDLE_PER_HOST)
        .retry(wreq::retry::Policy::never())
        .redirect(wreq::redirect::Policy::none())
        .build()
        .map(Arc::new)
        .map_err(|e| format!("failed to build wreq client for profile '{profile_name}': {e}"))
}

pub(crate) fn get_wreq_client(profile_name: &str) -> Result<Arc<WreqClient>, String> {
    let profile = if profile_name.eq_ignore_ascii_case(PASS_THROUGH_PROFILE) {
        None
    } else {
        crate::profiles::by_name(profile_name)
            .or_else(|| crate::profiles::by_name(FALLBACK_PROFILE))
    };
    let canonical = profile
        .map(|profile| profile.name.as_str())
        .unwrap_or(PASS_THROUGH_PROFILE);
    let pool_key = profile
        .map(crate::profiles::TlsProfile::pool_key)
        .unwrap_or_else(|| "default".to_owned());

    if let Some(client) = CLIENT_CACHE
        .lock()
        .map_err(|e| format!("client cache lock poisoned: {e}"))?
        .get(&pool_key)
        .cloned()
    {
        return Ok(client);
    }

    let client = build_wreq_client(canonical)?;
    let mut cache = CLIENT_CACHE
        .lock()
        .map_err(|e| format!("client cache lock poisoned: {e}"))?;
    Ok(Arc::clone(cache.entry(pool_key).or_insert(client)))
}

pub(crate) fn get_passthrough_client() -> Result<Arc<WreqClient>, String> {
    get_wreq_client(PASS_THROUGH_PROFILE)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn profile_aliases_share_one_client_pool() {
        let lower = get_wreq_client("chrome_120").expect("build lowercase profile");
        let upper = get_wreq_client("CHROME_120").expect("reuse canonical profile");
        assert!(Arc::ptr_eq(&lower, &upper));
    }

    #[test]
    fn unknown_profiles_use_the_default_transport() {
        let fallback = get_wreq_client(FALLBACK_PROFILE).expect("build fallback profile");
        let unknown = get_wreq_client("missing_profile").expect("use fallback profile");
        assert!(Arc::ptr_eq(&fallback, &unknown));
    }

    #[test]
    fn compatibility_aliases_share_their_wreq_profile_pool() {
        let alias = get_wreq_client("chrome_149_stable").expect("build alias client");
        let direct = get_wreq_client("chrome_149").expect("reuse direct profile client");
        assert!(Arc::ptr_eq(&alias, &direct));
    }
}
