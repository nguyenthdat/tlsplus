---
name: burp-suite-ui
description: >-
  Burp Suite UI and settings workflow for Kotlin/Swing Montoya extensions. Use
  when writing or reviewing Burp UI tabs, api.userInterface() integration,
  registerSuiteTab, registerSettingsPanel, SettingsPanel, SettingsPanelBuilder,
  Preferences-backed ExtensionSettings, TlsPlusTab, or visual polish for a Burp
  extension.
---

# Burp Suite UI And Settings

Use this skill when implementing or reviewing UI for a Burp Suite Montoya extension in Kotlin. The tlsplus project uses Kotlin/JVM, Swing, Montoya `2026.4`, and a Preferences-backed `ExtensionSettings` model.

Official docs to verify exact signatures:

- Montoya Javadoc: `https://portswigger.github.io/burp-extensions-montoya-api/javadoc/`
- Current project dependency: `net.portswigger.burp.extensions:montoya-api:2026.4`

## UI Entry Points

Common Montoya UI calls in `api.userInterface()`:

```kotlin
api.userInterface().applyThemeToComponent(component)
api.userInterface().registerSuiteTab("TLS+", component)
api.userInterface().registerSettingsPanel(settingsPanel)
api.userInterface().openSettingsWindow()

val requestEditor = api.userInterface().createHttpRequestEditor()
val responseEditor = api.userInterface().createHttpResponseEditor()
val rawEditor = api.userInterface().createRawEditor()
```

Use `registerSettingsPanel(SettingsPanel)` for Montoya `2026.4`. Do not use obsolete `registerSettingsProvider` examples.

## Suite Tab Pattern

Register the main extension tab from the extension entry point:

```kotlin
class TlsPlusExtension : BurpExtension {
    override fun initialize(api: MontoyaApi) {
        api.extension().setName("TLS+")

        val settings = ExtensionSettings(api.persistence().preferences())
        val core = TlsPlusCore { message -> api.logging().logToOutput(message) }
        val tab = TlsPlusTab(core, settings) { message -> api.logging().logToOutput(message) }

        api.userInterface().applyThemeToComponent(tab)
        api.userInterface().registerSuiteTab("TLS+", tab)
    }
}
```

Swing guidance:

- Prefer `JPanel(BorderLayout)`, `JTabbedPane`, `GridBagLayout`, `JSplitPane`, `JScrollPane`, and `JTable` over custom painting.
- Keep all long-running core, proxy, network, or file operations off the Event Dispatch Thread.
- Update Swing components from `SwingUtilities.invokeLater { ... }`.
- Prefer Burp's built-in editors from `createHttpRequestEditor`, `createHttpResponseEditor`, or `createRawEditor` when showing messages or raw data.
- Set `toolTipText`, accessible labels where practical, and clear status text for failure modes.
- Call `applyThemeToComponent` after constructing custom components and before registration.

## Settings Source Of Truth

For settings used by handlers or the Rust core, prefer a small wrapper around `api.persistence().preferences()`:

```kotlin
class ExtensionSettings(
    private val preferences: Preferences,
) {
    var passThroughOnly: Boolean
        get() = preferences.getBoolean(KEY_PASS_THROUGH_ONLY) ?: true
        set(value) = preferences.setBoolean(KEY_PASS_THROUGH_ONLY, value)

    var serverListenAddr: String
        get() = preferences.getString(KEY_SERVER_LISTEN_ADDR) ?: "127.0.0.1:43117"
        set(value) = preferences.setString(KEY_SERVER_LISTEN_ADDR, value)

    companion object {
        private const val KEY_PASS_THROUGH_ONLY = "tlsplus.passThroughOnly"
        private const val KEY_SERVER_LISTEN_ADDR = "tlsplus.serverListenAddr"
    }
}
```

Preferences methods in Montoya `2026.4` include:

- `getString`, `setString`, `deleteString`, `stringKeys`
- `getBoolean`, `setBoolean`, `deleteBoolean`, `booleanKeys`
- `getInteger`, `setInteger`, `deleteInteger`, `integerKeys`
- `getLong`, `setLong`, `deleteLong`, `longKeys`

Use namespaced keys like `tlsplus.profileName`. Keep defaults in one place. Validate user input before writing to preferences.

## Burp Settings Dialog Pattern

There are two good patterns. Choose one and document why.

### Pattern A: Custom SettingsPanel Backed By ExtensionSettings

Use this when settings must immediately affect handlers or background services that already read `ExtensionSettings`.

```kotlin
import burp.api.montoya.ui.settings.SettingsPanel
import javax.swing.JCheckBox
import javax.swing.JComponent
import javax.swing.JPanel

class TlsPlusSettingsPanel(
    private val settings: ExtensionSettings,
) : SettingsPanel {
    private val passThroughOnly = JCheckBox("Pass-through only", settings.passThroughOnly).apply {
        addActionListener { settings.passThroughOnly = isSelected }
    }

    private val panel = JPanel().apply {
        add(passThroughOnly)
    }

    override fun uiComponent(): JComponent = panel

    override fun keywords(): Set<String> = setOf("tlsplus", "tls", "ja4", "proxy")
}

api.userInterface().registerSettingsPanel(TlsPlusSettingsPanel(settings))
```

### Pattern B: SettingsPanelBuilder With Built-In Persistence

Use this when the settings panel itself can be the data source, or when the code reads from the returned `SettingsPanelWithData` object.

```kotlin
import burp.api.montoya.ui.settings.SettingsPanelBuilder
import burp.api.montoya.ui.settings.SettingsPanelPersistence
import burp.api.montoya.ui.settings.SettingsPanelSetting

val tlsSettingsPanel = SettingsPanelBuilder.settingsPanel()
    .withTitle("TLS+")
    .withDescription("TLS fingerprinting and proxy behavior.")
    .withPersistence(SettingsPanelPersistence.PROJECT_SETTINGS)
    .withSetting(SettingsPanelSetting.booleanSetting("Keep the extension in safe pass-through mode", "passThroughOnly", true))
    .withSetting(SettingsPanelSetting.stringSetting("Local proxy listen address", "serverListenAddr", "127.0.0.1:43117"))
    .withSetting(SettingsPanelSetting.listSetting("Active TLS profile", "profileName", listOf("pass-through", "chrome", "firefox"), "pass-through"))
    .withKeywords("tlsplus", "tls", "ja4", "proxy")
    .build()

api.userInterface().registerSettingsPanel(tlsSettingsPanel)

val passThrough = tlsSettingsPanel.getBoolean("passThroughOnly")
val listenAddr = tlsSettingsPanel.getString("serverListenAddr")
```

Persistence choices:

- `SettingsPanelPersistence.PROJECT_SETTINGS`: project-specific values; usually best for proxy/listener/fingerprint behavior.
- `SettingsPanelPersistence.USER_SETTINGS`: user-wide values; useful for personal UI preferences.
- `SettingsPanelPersistence.NONE`: volatile settings only.

Do not mix `SettingsPanelWithData` and `Preferences` for the same key unless there is explicit synchronization code.

## Layout Checklist

- Put high-risk toggles such as interception, pass-through mode, and active proxy status near the top.
- Separate configuration, diagnostics, JA4 computation, and proxy testing into tabs or clearly titled panels.
- Use visible status text for save/start/stop actions.
- Disable buttons while a background action is running, then re-enable on completion.
- Show validation errors inline instead of only logging to Burp output.
- Ensure text areas wrap or scroll, and large outputs do not expand the window uncontrollably.

## Verification

Run when feasible:

```bash
./gradlew build
```

Manual Burp checks:

- Load `build/libs/tlsplus-extension.jar` in Burp Extender.
- Confirm the `TLS+` suite tab appears and respects Burp theme/font size.
- Open Burp Settings and search `tlsplus`; confirm the settings panel appears if registered.
- Change each setting, reload the extension, and confirm persisted values are restored.
- Confirm handlers read the updated settings by triggering proxy or HTTP flows.
