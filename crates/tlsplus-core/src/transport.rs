use std::collections::HashMap;
use std::sync::{Arc, LazyLock, Mutex};

use bytes::Bytes;
use http_body_util::BodyExt;

pub(crate) type WreqClient = wreq::Client;

static CLIENT_CACHE: LazyLock<Mutex<HashMap<String, Arc<WreqClient>>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

fn map_profile_to_wreq_emulation(profile: &str) -> Option<wreq_util::Profile> {
    match profile {
        "chrome_149" | "chrome_149_stable" => Some(wreq_util::Profile::Chrome149),
        "chrome_120" => Some(wreq_util::Profile::Chrome120),
        "chrome_130" => Some(wreq_util::Profile::Chrome130),
        "firefox_current" | "firefox_130" | "firefox_135" => Some(wreq_util::Profile::Firefox135),
        "safari_18" => Some(wreq_util::Profile::Safari18_5),
        "safari_17" => Some(wreq_util::Profile::Safari17_0),
        "edge_120" => Some(wreq_util::Profile::Edge140),
        "ios_safari_17" => Some(wreq_util::Profile::SafariIos17_2),
        "android_chrome" => Some(wreq_util::Profile::Chrome149),
        "python_urllib3" | "curl_8" => Some(wreq_util::Profile::OkHttp5),
        "rustls_default" => None,
        _ => None,
    }
}

fn build_wreq_client(profile_name: &str) -> Result<Arc<WreqClient>, String> {
    let mut builder = wreq::Client::builder();

    if let Some(emu) = map_profile_to_wreq_emulation(profile_name) {
        builder = builder.emulation(emu);
    }

    builder
        .build()
        .map(Arc::new)
        .map_err(|e| format!("failed to build wreq client for profile '{profile_name}': {e}"))
}

pub(crate) fn get_wreq_client(profile_name: &str) -> Result<Arc<WreqClient>, String> {
    let mut cache = CLIENT_CACHE
        .lock()
        .map_err(|e| format!("client cache lock poisoned: {e}"))?;

    if let Some(client) = cache.get(profile_name) {
        return Ok(Arc::clone(client));
    }

    let client = build_wreq_client(profile_name)?;
    cache.insert(profile_name.to_owned(), Arc::clone(&client));
    Ok(client)
}

pub(crate) fn get_passthrough_client() -> Result<Arc<WreqClient>, String> {
    get_wreq_client("pass-through")
}
