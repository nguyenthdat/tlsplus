package com.tlsplus.burp.ui

import burp.api.montoya.ui.settings.SettingsPanel
import com.tlsplus.burp.core.TlsPlusCore
import com.tlsplus.burp.settings.ExtensionSettings
import java.awt.Component
import java.awt.GridBagConstraints
import java.awt.GridBagLayout
import java.awt.Insets
import javax.swing.BorderFactory
import javax.swing.JCheckBox
import javax.swing.JComboBox
import javax.swing.JComponent
import javax.swing.JLabel
import javax.swing.JPanel
import javax.swing.JTextField
import javax.swing.SwingConstants

/**
 * TLS+ panel for Burp's native Settings dialog (Montoya 2026.4).
 *
 * Pattern A from the burp-suite-ui skill: a custom [SettingsPanel] backed directly
 * by the shared [ExtensionSettings] (Preferences) so that edits made here are read
 * by the same handlers and background services that the suite tab configures. This
 * avoids a second, unsynchronized settings store.
 *
 * Changes are written to [ExtensionSettings] property setters immediately on user
 * interaction. Burp applies its own theme to this panel when it is rendered, so we
 * keep components standard and avoid hardcoding colors here.
 */
class TlsPlusSettingsPanel(
    private val settings: ExtensionSettings,
    core: TlsPlusCore,
) : SettingsPanel {
    private val passThroughOnly =
        JCheckBox("Pass-through only (safe mode)", settings.passThroughOnly).apply {
            toolTipText = "When enabled, all traffic passes through Burp's normal TLS stack (no spoofing)."
            addActionListener { settings.passThroughOnly = isSelected }
        }

    private val preserveHeaderOrder =
        JCheckBox("Preserve header order", settings.preserveHeaderOrder).apply {
            toolTipText = "Forward request headers in their original observed order."
            addActionListener { settings.preserveHeaderOrder = isSelected }
        }

    private val profile =
        JComboBox(core.profiles().toTypedArray()).apply {
            selectedItem = settings.profileName
            toolTipText = "Active TLS fingerprint profile used by the spoofing proxy."
            addActionListener {
                settings.profileName = selectedItem?.toString() ?: settings.profileName
            }
        }

    private val listenAddr =
        JTextField(settings.serverListenAddr, 24).apply {
            toolTipText = "Local listen address for the embedded Rust proxy (host:port)."
            // Persist on focus loss / edit completion via the action + property setter.
            addActionListener { commitListenAddr() }
            addFocusListener(
                object : java.awt.event.FocusAdapter() {
                    override fun focusLost(e: java.awt.event.FocusEvent) = commitListenAddr()
                },
            )
        }

    private val panel: JPanel =
        JPanel(GridBagLayout()).apply {
            border = BorderFactory.createEmptyBorder(12, 12, 12, 12)
            val c = constraints()
            var row = 0

            addRow(c, row, "Mode", passThroughOnly)
            row += 1
            addRow(c, row, "Header order", preserveHeaderOrder)
            row += 1
            addRow(c, row, "Profile", profile)
            row += 1
            addRow(c, row, "Listen address", listenAddr)
        }

    override fun uiComponent(): JComponent = panel

    override fun keywords(): Set<String> = setOf("tlsplus", "tls", "ja4", "ja3", "proxy", "fingerprint", "spoof")

    // ── Helpers ────────────────────────────────────────────────────────────

    private fun commitListenAddr() {
        val value = listenAddr.text.trim().ifBlank { "127.0.0.1:43117" }
        settings.serverListenAddr = value
        listenAddr.text = value
    }

    private fun constraints(): GridBagConstraints =
        GridBagConstraints().apply {
            fill = GridBagConstraints.HORIZONTAL
            insets = Insets(8, 8, 8, 8)
            anchor = GridBagConstraints.WEST
        }

    private fun JPanel.addRow(
        c: GridBagConstraints,
        row: Int,
        label: String,
        component: Component,
    ) {
        c.gridx = 0
        c.gridy = row
        c.weightx = 0.0
        add(
            JLabel(label).apply { horizontalAlignment = SwingConstants.LEFT },
            c,
        )
        c.gridx = 1
        c.weightx = 1.0
        add(component, c)
    }
}
