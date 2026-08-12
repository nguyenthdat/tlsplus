//! wreq-util profile catalog plus stable TLS+ compatibility aliases.

use std::sync::LazyLock;

use wreq::IntoEmulation;
use wreq_util::{Emulation, Platform, Profile};

#[derive(Debug, Clone)]
pub struct TlsProfile {
    pub name: String,
    pub description: String,
    wreq_profile: Option<Profile>,
    platform: Option<Platform>,
}

impl TlsProfile {
    fn from_wreq(profile: Profile) -> Self {
        Self {
            name: profile.name().to_owned(),
            description: format!("{} via wreq-util", display_name(profile.name())),
            wreq_profile: Some(profile),
            platform: None,
        }
    }

    fn alias(
        name: &str,
        description: &str,
        wreq_profile: Option<Profile>,
        platform: Option<Platform>,
    ) -> Self {
        Self {
            name: name.to_owned(),
            description: description.to_owned(),
            wreq_profile,
            platform,
        }
    }

    #[must_use]
    pub fn cipher_count(&self) -> u32 {
        self.emulation()
            .and_then(|emulation| emulation.tls_options)
            .and_then(|options| options.cipher_list)
            .map(|ciphers| ciphers.split(':').count() as u32)
            .unwrap_or(1)
    }

    #[must_use]
    pub fn alpn_protocols(&self) -> Vec<String> {
        self.emulation()
            .and_then(|emulation| emulation.tls_options)
            .and_then(|options| options.alpn_protocols)
            .map(|protocols| {
                protocols
                    .iter()
                    .filter_map(|protocol| {
                        if *protocol == b"h2"[..] {
                            Some("h2".to_owned())
                        } else if *protocol == b"http/1.1"[..] {
                            Some("http/1.1".to_owned())
                        } else {
                            None
                        }
                    })
                    .collect()
            })
            .unwrap_or_else(|| vec!["h2".to_owned(), "http/1.1".to_owned()])
    }

    pub(crate) fn emulation(&self) -> Option<wreq::Emulation> {
        let profile = self.wreq_profile?;
        let emulation = match self.platform {
            Some(platform) => Emulation::builder()
                .profile(profile)
                .platform(platform)
                .build(),
            None => Emulation::builder().profile(profile).build(),
        };
        Some(emulation.into_emulation())
    }

    pub(crate) fn pool_key(&self) -> String {
        match (self.wreq_profile, self.platform) {
            (Some(profile), Some(platform)) => {
                format!("{}@{}", profile.name(), platform.name())
            }
            (Some(profile), None) => profile.name().to_owned(),
            (None, _) => "default".to_owned(),
        }
    }
}

fn display_name(name: &str) -> String {
    let (family, version) = name.split_once('_').unwrap_or((name, ""));
    let family = match family {
        "chrome" => "Chrome",
        "edge" => "Edge",
        "firefox" => "Firefox",
        "opera" => "Opera",
        "safari" => "Safari",
        "okhttp" => "OkHttp",
        other => other,
    };
    if version.is_empty() {
        family.to_owned()
    } else {
        format!("{family} {}", version.replace('_', " "))
    }
}

macro_rules! compatibility_aliases {
    () => {
        vec![
            TlsProfile::alias(
                "chrome_149_stable",
                "Chrome 149 stable alias",
                Some(Profile::Chrome149),
                None,
            ),
            TlsProfile::alias(
                "firefox_current",
                "Newest supported Firefox profile",
                Some(Profile::Firefox151),
                None,
            ),
            TlsProfile::alias(
                "firefox_130",
                "Nearest supported Firefox profile (Firefox 128)",
                Some(Profile::Firefox128),
                None,
            ),
            TlsProfile::alias(
                "safari_17",
                "Nearest supported Safari profile (Safari 17.5)",
                Some(Profile::Safari17_5),
                None,
            ),
            TlsProfile::alias(
                "edge_120",
                "Nearest supported Edge profile (Edge 122)",
                Some(Profile::Edge122),
                None,
            ),
            TlsProfile::alias(
                "ios_safari_17",
                "iOS Safari 17.2",
                Some(Profile::SafariIos17_2),
                Some(Platform::IOS),
            ),
            TlsProfile::alias(
                "android_chrome",
                "Android Chrome 149",
                Some(Profile::Chrome149),
                Some(Platform::Android),
            ),
            TlsProfile::alias(
                "python_urllib3",
                "Default wreq transport; no Python identity is available",
                None,
                None,
            ),
            TlsProfile::alias(
                "rustls_default",
                "Default wreq transport; no rustls identity is available",
                None,
                None,
            ),
            TlsProfile::alias(
                "curl_8",
                "Default wreq transport; no curl identity is available",
                None,
                None,
            ),
        ]
    };
}

static PROFILES: LazyLock<Vec<TlsProfile>> = LazyLock::new(|| {
    let mut profiles: Vec<_> = Profile::VARIANTS
        .iter()
        .copied()
        .map(TlsProfile::from_wreq)
        .collect();
    profiles.extend(compatibility_aliases!());
    profiles
});

pub fn all_profiles() -> &'static [TlsProfile] {
    &PROFILES
}

pub fn by_name(name: &str) -> Option<&'static TlsProfile> {
    PROFILES
        .iter()
        .find(|profile| profile.name.eq_ignore_ascii_case(name))
}

pub fn profile_names() -> Vec<String> {
    PROFILES
        .iter()
        .map(|profile| profile.name.clone())
        .collect()
}

pub(crate) fn wreq_emulation(name: &str) -> Option<wreq::Emulation> {
    by_name(name).and_then(TlsProfile::emulation)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn catalog_includes_every_wreq_util_profile() {
        for profile in Profile::VARIANTS {
            assert!(by_name(profile.name()).is_some());
        }
    }

    #[test]
    fn profile_names_are_unique() {
        let names = profile_names();
        for (index, name) in names.iter().enumerate() {
            assert!(!names[..index].iter().any(|other| other == name));
        }
    }

    #[test]
    fn non_browser_profiles_share_default_pool_key() {
        for name in ["python_urllib3", "rustls_default", "curl_8"] {
            let profile = by_name(name).expect("compatibility profile exists");
            assert!(profile.emulation().is_none());
            assert_eq!(profile.pool_key(), "default");
        }
    }
}
