package com.tlsplus.burp.settings

import burp.api.montoya.persistence.Preferences

class ExtensionSettings(
    private val preferences: Preferences,
) {
    var passThroughOnly: Boolean
        get() = preferences.getBoolean(KEY_PASS_THROUGH_ONLY) ?: false // default: active mode
        set(value) = preferences.setBoolean(KEY_PASS_THROUGH_ONLY, value)

    var preserveHeaderOrder: Boolean
        get() = preferences.getBoolean(KEY_PRESERVE_HEADER_ORDER) ?: true
        set(value) = preferences.setBoolean(KEY_PRESERVE_HEADER_ORDER, value)

    var profileName: String
        get() = preferences.getString(KEY_PROFILE_NAME) ?: "chrome_149"
        set(value) = preferences.setString(KEY_PROFILE_NAME, value)

    var serverListenAddr: String
        get() = preferences.getString(KEY_SERVER_LISTEN_ADDR) ?: "127.0.0.1:43117"
        set(value) = preferences.setString(KEY_SERVER_LISTEN_ADDR, value)

    companion object {
        private const val KEY_PASS_THROUGH_ONLY = "tlsplus.passThroughOnly"
        private const val KEY_PRESERVE_HEADER_ORDER = "tlsplus.preserveHeaderOrder"
        private const val KEY_PROFILE_NAME = "tlsplus.profileName"
        private const val KEY_SERVER_LISTEN_ADDR = "tlsplus.serverListenAddr"
    }
}
