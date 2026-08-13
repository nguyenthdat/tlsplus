package com.tlsplus.burp.ui

import com.tlsplus.burp.core.TlsPlusCore
import com.tlsplus.burp.settings.ExtensionSettings
import com.tlsplus.core.ProxyResponse
import java.awt.BorderLayout
import java.awt.Color
import java.awt.Component
import java.awt.Dimension
import java.awt.FlowLayout
import java.awt.Font
import java.awt.GridBagConstraints
import java.awt.GridBagLayout
import java.awt.Insets
import javax.swing.BorderFactory
import javax.swing.Box
import javax.swing.BoxLayout
import javax.swing.JButton
import javax.swing.JCheckBox
import javax.swing.JComboBox
import javax.swing.JComponent
import javax.swing.JLabel
import javax.swing.JPanel
import javax.swing.JScrollPane
import javax.swing.JTabbedPane
import javax.swing.JTextArea
import javax.swing.JTextField
import javax.swing.SwingConstants
import javax.swing.SwingUtilities
import javax.swing.Timer

/**
 * Main TLS+ suite tab.
 *
 * Visual overhaul targeting Burp's dark theme (Montoya 2026.4). The UI is split
 * into a top status bar (proxy + core indicators), a tabbed configuration area
 * (Config / JA4 / Proxy Test), and an always-visible monospace output console at
 * the bottom.
 *
 * Theme strategy: Burp's [burp.api.montoya.ui.UserInterface.applyThemeToComponent]
 * recolors most standard Swing components and the [javax.swing.UIManager] defaults.
 * For surfaces Burp does not always reach (custom status bar, monospace consoles),
 * we read [javax.swing.UIManager] colors first and fall back to dark-theme constants.
 *
 * Threading: all FFI/network calls (server start/stop, JA4/JA3 compute, proxy test)
 * run on background threads; UI mutations are marshalled back via
 * [SwingUtilities.invokeLater].
 */
class TlsPlusTab(
    private val core: TlsPlusCore,
    private val settings: ExtensionSettings,
    private val log: (String) -> Unit = {},
) : JPanel(BorderLayout(0, 0)) {
    // ── Theme palette ─────────────────────────────────────────────────────
    // Prefer UIManager (set by Burp's applyThemeToComponent) with dark fallbacks.

    private val accent = Color(0xFF, 0x66, 0x22)
    private val panelBg = uiColor("Panel.background", Color(0x2B, 0x2B, 0x2B))
    private val labelFg = uiColor("Label.foreground", Color(0xBB, 0xBB, 0xBB))
    private val inputBg = uiColor("TextField.background", Color(0x3C, 0x3F, 0x41))
    private val inputFg = uiColor("TextField.foreground", Color(0xBB, 0xBB, 0xBB))
    private val consoleBg = uiColor("TextArea.background", Color(0x2B, 0x2B, 0x2B))
    private val consoleFg = Color(0xA9, 0xB7, 0xC6)
    private val statusBarBg = lighten(panelBg, 0x10)

    private val mono = Font(Font.MONOSPACED, Font.PLAIN, 13)

    // ── Status bar indicators ───────────────────────────────────────────────

    private val proxyDot = statusDot()
    private val proxyStatusLabel = JLabel("checking…").apply { foreground = labelFg }
    private val coreDot = statusDot()
    private val coreStatusLabel = JLabel("checking…").apply { foreground = labelFg }

    // ── Config tab fields ─────────────────────────────────────────────────

    private val passThroughOnly = themedCheckBox("Pass-through only (safe mode)", settings.passThroughOnly)
    private val preserveHeaderOrder = themedCheckBox("Preserve header order", settings.preserveHeaderOrder)
    private val profiles = themedCombo(core.profiles().toTypedArray())
    private val listenAddr = themedField(settings.serverListenAddr, 25)
    private val startButton = JButton("Start")
    private val stopButton = JButton("Stop")

    // Tracks the last-known server running state so the Start button can be
    // disabled while the proxy is up. Kept in sync via refreshStatus().
    @Volatile
    private var serverRunning = false

    // Live status poller. Each tick calls refreshStatus(), which queries the
    // authoritative core.serverStatus() off the EDT and marshals UI updates back.
    // Lifecycle bound to addNotify()/removeNotify() so it never leaks when the tab
    // is detached, and surfaces the auto-start state within ~2s of load.
    private val statusTimer =
        Timer(STATUS_POLL_MS) { refreshStatus() }.apply {
            isRepeats = true
        }

    // ── JA4 tab fields ────────────────────────────────────────────────────

    private val clientHelloHex =
        JTextArea(6, 60).apply {
            lineWrap = true
            wrapStyleWord = true
            font = mono
            background = inputBg
            foreground = inputFg
            caretColor = inputFg
            border = BorderFactory.createEmptyBorder(6, 8, 6, 8)
            toolTipText = "Paste TLS ClientHello hex. TCP input must include the 5-byte TLS record header."
        }
    private val computeJa4Button = JButton("Compute JA4")
    private val computeJa3Button = JButton("Compute JA3")

    // ── Proxy test tab fields ───────────────────────────────────────────────

    private val proxyTestUrl = themedField("https://httpbin.org/get", 40)
    private val proxyTestMethod = themedCombo(arrayOf("GET", "POST", "PUT", "DELETE", "HEAD"))
    private val proxyTestProfile = themedCombo(core.profiles().toTypedArray())
    private val sendRequestButton = JButton("Send Request")
    private val proxyTestResult =
        JTextArea(10, 80).apply {
            isEditable = false
            lineWrap = true
            wrapStyleWord = true
            font = mono
            background = consoleBg
            foreground = consoleFg
            caretColor = consoleFg
            border = BorderFactory.createEmptyBorder(6, 8, 6, 8)
        }

    // ── Output console (always visible, bottom) ─────────────────────────────

    private val output =
        JTextArea().apply {
            isEditable = false
            lineWrap = true
            wrapStyleWord = true
            font = mono
            background = consoleBg
            foreground = consoleFg
            caretColor = consoleFg
            border = BorderFactory.createEmptyBorder(8, 10, 8, 10)
            text = core.describeCore()
        }

    init {
        background = panelBg
        border = BorderFactory.createEmptyBorder(0, 0, 0, 0)

        add(statusBar(), BorderLayout.NORTH)
        add(centerContent(), BorderLayout.CENTER)

        wireActions()
        // Populate status indicators off the EDT.
        refreshStatus()
    }

    // ── Live status lifecycle ─────────────────────────────────────────────────

    /**
     * Called by Swing when the tab is attached to a displayable hierarchy. We do
     * an immediate authoritative refresh (so the auto-start state shows without a
     * click) and start the polling timer to keep the header in sync with external
     * changes (auto-start, settings-panel start/stop, etc.).
     */
    override fun addNotify() {
        super.addNotify()
        refreshStatus()
        statusTimer.start()
    }

    /**
     * Called by Swing when the tab is detached. Stop the poller so no background
     * work or EDT callbacks continue against a dead component.
     */
    override fun removeNotify() {
        statusTimer.stop()
        super.removeNotify()
    }

    // ── Layout: status bar ──────────────────────────────────────────────────

    private fun statusBar(): JComponent {
        val bar =
            JPanel(FlowLayout(FlowLayout.LEFT, 18, 0)).apply {
                background = statusBarBg
                border = BorderFactory.createEmptyBorder(8, 12, 8, 12)
            }

        val brand =
            JLabel("TLS+").apply {
                foreground = accent
                font = font.deriveFont(Font.BOLD, 14f)
                border = BorderFactory.createEmptyBorder(0, 0, 0, 6)
            }

        bar.add(brand)
        bar.add(indicatorGroup("Proxy", proxyDot, proxyStatusLabel))
        bar.add(indicatorGroup("Core", coreDot, coreStatusLabel))
        return bar
    }

    private fun indicatorGroup(
        caption: String,
        dot: JLabel,
        status: JLabel,
    ): JComponent =
        JPanel(FlowLayout(FlowLayout.LEFT, 6, 0)).apply {
            isOpaque = false
            add(dot)
            add(
                JLabel("$caption:").apply {
                    foreground = labelFg
                    font = font.deriveFont(Font.BOLD)
                },
            )
            add(status)
        }

    // ── Layout: center (tabs + output) ──────────────────────────────────────

    private fun centerContent(): JComponent {
        val tabs =
            JTabbedPane().apply {
                background = panelBg
                foreground = labelFg
                addTab("Config", wrapTab(configPanel()))
                addTab("JA4 / JA3", wrapTab(ja4Panel()))
                addTab("Proxy Test", wrapTab(proxyTestPanel()))
            }

        val outputScroll =
            JScrollPane(output).apply {
                preferredSize = Dimension(0, 200)
                border = titled("Output Console")
                background = panelBg
                viewport.background = consoleBg
            }

        val center =
            JPanel(BorderLayout(0, 8)).apply {
                background = panelBg
                border = BorderFactory.createEmptyBorder(10, 12, 12, 12)
                add(tabs, BorderLayout.CENTER)
                add(outputScroll, BorderLayout.SOUTH)
            }
        return center
    }

    private fun wrapTab(content: JComponent): JComponent =
        JPanel(BorderLayout()).apply {
            background = panelBg
            border = BorderFactory.createEmptyBorder(10, 10, 10, 10)
            add(content, BorderLayout.NORTH)
        }

    // ── Config tab ──────────────────────────────────────────────────────────

    private fun configPanel(): JComponent {
        val panel =
            JPanel(GridBagLayout()).apply {
                background = panelBg
                border = titled("Proxy Configuration")
            }
        val c = gbc()
        var row = 0

        // Row: pass-through mode + description.
        c.gridx = 0
        c.gridy = row
        c.gridwidth = 2
        c.weightx = 1.0
        panel.add(passThroughOnly, c)
        row += 1

        c.gridy = row
        panel.add(
            hintLabel("When enabled, all traffic passes through Burp's normal TLS stack (no spoofing)."),
            c,
        )
        row += 1

        // Row: preserve header order.
        c.gridy = row
        panel.add(preserveHeaderOrder, c)
        row += 1

        c.gridwidth = 1

        // Row: profile dropdown + details button.
        profiles.selectedItem = settings.profileName
        val profileRow =
            JPanel(FlowLayout(FlowLayout.LEFT, 4, 0)).apply {
                isOpaque = false
                add(profiles)
                add(
                    JButton("Details").apply {
                        addActionListener { showProfileDetails() }
                    },
                )
            }
        addLabeledRow(panel, c, row, "Profile", profileRow)
        row += 1

        // Row: listen address + start/stop.
        val addrRow =
            JPanel(FlowLayout(FlowLayout.LEFT, 4, 0)).apply {
                isOpaque = false
                add(listenAddr)
                add(startButton)
                add(stopButton)
            }
        addLabeledRow(panel, c, row, "Listen address", addrRow)
        row += 1

        // Row: global actions.
        val actionRow =
            JPanel(FlowLayout(FlowLayout.LEFT, 4, 0)).apply {
                isOpaque = false
                add(
                    JButton("Refresh Core").apply {
                        addActionListener { onRefreshCore() }
                    },
                )
                add(
                    JButton("Save Settings").apply {
                        addActionListener { onSaveSettings() }
                    },
                )
            }
        addLabeledRow(panel, c, row, "Actions", actionRow)

        return panel
    }

    // ── JA4 / JA3 tab ────────────────────────────────────────────────────────

    private fun ja4Panel(): JComponent {
        val panel =
            JPanel(BorderLayout(0, 8)).apply {
                background = panelBg
                border = titled("JA4 / JA3 Fingerprint Computation")
            }

        val hexScroll =
            JScrollPane(clientHelloHex).apply {
                background = panelBg
                viewport.background = inputBg
                preferredSize = Dimension(720, 130)
                border = BorderFactory.createLineBorder(lighten(panelBg, 0x18))
            }
        panel.add(hexScroll, BorderLayout.NORTH)

        val center =
            JPanel().apply {
                isOpaque = false
                layout = BoxLayout(this, BoxLayout.Y_AXIS)
            }
        center.add(
            hintLabel(
                "Paste raw TLS ClientHello bytes as hex. TCP: include the 5-byte record header " +
                    "(16 03 01 ...). Computes JA4, JA4_r, JA4_o, JA4_or, JA4_s1, JA4_s1r in one call.",
            ),
        )
        center.add(Box.createVerticalStrut(8))

        val actions =
            JPanel(FlowLayout(FlowLayout.LEFT, 4, 0)).apply {
                isOpaque = false
                add(computeJa4Button)
                add(computeJa3Button)
                add(
                    JButton("Clear").apply {
                        addActionListener {
                            clientHelloHex.text = ""
                            setOutput(core.describeCore())
                        }
                    },
                )
            }
        center.add(actions)
        panel.add(center, BorderLayout.CENTER)

        return panel
    }

    // ── Proxy Test tab ────────────────────────────────────────────────────────

    private fun proxyTestPanel(): JComponent {
        val panel =
            JPanel(GridBagLayout()).apply {
                background = panelBg
                border = titled("Outbound Proxy Test")
            }
        val c = gbc()
        var row = 0

        val targetRow =
            JPanel(FlowLayout(FlowLayout.LEFT, 4, 0)).apply {
                isOpaque = false
                add(proxyTestMethod)
                add(proxyTestUrl)
            }
        addLabeledRow(panel, c, row, "Target", targetRow)
        row += 1

        proxyTestProfile.selectedItem = settings.profileName
        addLabeledRow(panel, c, row, "Profile", profileFlow(proxyTestProfile))
        row += 1

        val actions =
            JPanel(FlowLayout(FlowLayout.LEFT, 4, 0)).apply {
                isOpaque = false
                add(sendRequestButton)
                add(
                    JButton("Clear").apply {
                        addActionListener { proxyTestResult.text = "" }
                    },
                )
            }
        addLabeledRow(panel, c, row, "Actions", actions)
        row += 1

        val responseScroll =
            JScrollPane(proxyTestResult).apply {
                background = panelBg
                viewport.background = consoleBg
                preferredSize = Dimension(720, 200)
                border = BorderFactory.createLineBorder(lighten(panelBg, 0x18))
            }
        c.gridx = 0
        c.gridy = row
        c.gridwidth = 2
        c.weightx = 1.0
        panel.add(responseScroll, c)
        row += 1

        c.gridy = row
        panel.add(
            hintLabel(
                "Sends a direct outbound request through the Rust hyper + BoringSSL client, " +
                    "bypassing Burp's HTTP stack. Same engine the local proxy uses for forwarding.",
            ),
            c,
        )

        return panel
    }

    private fun profileFlow(combo: JComboBox<String>): JComponent =
        JPanel(FlowLayout(FlowLayout.LEFT, 4, 0)).apply {
            isOpaque = false
            add(combo)
        }

    // ── Action wiring ───────────────────────────────────────────────────────

    private fun wireActions() {
        passThroughOnly.addActionListener { settings.passThroughOnly = passThroughOnly.isSelected }
        preserveHeaderOrder.addActionListener { settings.preserveHeaderOrder = preserveHeaderOrder.isSelected }
        profiles.addActionListener {
            settings.profileName = profiles.selectedItem?.toString() ?: "pass-through"
        }

        startButton.addActionListener { onStartServer() }
        stopButton.addActionListener { onStopServer() }

        computeJa4Button.addActionListener { onComputeJa4() }
        computeJa3Button.addActionListener { onComputeJa3() }
        sendRequestButton.addActionListener { onSendProxyRequest() }
    }

    private fun onRefreshCore() {
        setOutput("Refreshing core…")
        runBackground {
            val info = core.describeCore()
            SwingUtilities.invokeLater {
                setOutput(info)
                refreshStatus()
            }
        }
    }

    private fun onSaveSettings() {
        settings.serverListenAddr = listenAddr.text.trim().ifBlank { "127.0.0.1:43117" }
        settings.profileName = profiles.selectedItem?.toString() ?: "pass-through"
        settings.passThroughOnly = passThroughOnly.isSelected
        settings.preserveHeaderOrder = preserveHeaderOrder.isSelected
        listenAddr.text = settings.serverListenAddr
        appendOutput("Settings saved.")
    }

    private fun onStartServer() {
        val addr = listenAddr.text.trim().ifBlank { "127.0.0.1:43117" }
        settings.serverListenAddr = addr
        startButton.isEnabled = false
        stopButton.isEnabled = false
        setOutput("Starting proxy on $addr …")
        runBackground {
            val result = core.startServer(addr)
            if (result.status?.`running` == true) {
                result.status.`listenAddr`?.let { settings.serverListenAddr = it }
            }
            SwingUtilities.invokeLater {
                setOutput(result.output)
                refreshStatus()
            }
        }
    }

    private fun onStopServer() {
        startButton.isEnabled = false
        stopButton.isEnabled = false
        setOutput("Stopping proxy …")
        runBackground {
            val result = core.stopServer()
            SwingUtilities.invokeLater {
                setOutput(result)
                refreshStatus()
            }
        }
    }

    private fun showProfileDetails() {
        val name = profiles.selectedItem?.toString() ?: return
        setOutput("Loading profile '$name' …")
        runBackground {
            val info = core.profileInfo(name)
            val text =
                if (info == null) {
                    "No profile details available for '$name'."
                } else {
                    buildString {
                        appendLine("Profile: ${info.`name`}")
                        appendLine("Description: ${info.`description`}")
                        appendLine("Cipher count: ${info.`cipherCount`}")
                        appendLine("ALPN protocols: ${info.`alpnProtocols`.joinToString(", ").ifBlank { "(none)" }}")
                    }
                }
            SwingUtilities.invokeLater { setOutput(text) }
        }
    }

    private fun onComputeJa4() {
        val hex = clientHelloHex.text
        toggleJa4Buttons(false)
        setOutput("Computing JA4 …")
        runBackground {
            val result = core.computeClientHelloHex(hex)
            SwingUtilities.invokeLater {
                setOutput(result)
                toggleJa4Buttons(true)
            }
        }
    }

    private fun onComputeJa3() {
        val hex = clientHelloHex.text
        toggleJa4Buttons(false)
        setOutput("Computing JA3 …")
        runBackground {
            val result = core.computeJa3ClientHello(hex)
            SwingUtilities.invokeLater {
                setOutput(result)
                toggleJa4Buttons(true)
            }
        }
    }

    private fun onSendProxyRequest() {
        val method = proxyTestMethod.selectedItem?.toString() ?: "GET"
        val url = proxyTestUrl.text.trim()
        val profile = proxyTestProfile.selectedItem?.toString() ?: "pass-through"
        sendRequestButton.isEnabled = false
        proxyTestResult.text = "Sending request to $url …"
        runBackground {
            val response =
                core.sendProxyRequest(
                    method = method,
                    url = url,
                    headers =
                        listOf(
                            "User-Agent: TLS+/0.2.0",
                            "Accept: */*",
                        ),
                    body = ByteArray(0),
                    profile = profile,
                    timeoutSecs = 30,
                )
            SwingUtilities.invokeLater {
                proxyTestResult.text = formatProxyResponse(response)
                proxyTestResult.caretPosition = 0
                sendRequestButton.isEnabled = true
            }
        }
    }

    private fun toggleJa4Buttons(enabled: Boolean) {
        computeJa4Button.isEnabled = enabled
        computeJa3Button.isEnabled = enabled
    }

    // ── Status refresh ────────────────────────────────────────────────────────

    /**
     * Authoritative status refresh. The proxy indicator is driven by the
     * non-mutating [TlsPlusCore.serverStatus] query (real running flag + real
     * listen address), NOT by scanning the Output Console text. The core
     * indicator continues to come from [TlsPlusCore.shortStatus].
     *
     * All FFI runs on a background worker; UI mutations are marshalled back to the
     * EDT. Safe to call repeatedly (it's the timer's action and the post-action
     * hook), and cheap enough to poll at [STATUS_POLL_MS]. Public so the extension
     * can nudge the header immediately after auto-start completes.
     */
    fun refreshStatus() {
        runBackground {
            val coreStatus = core.shortStatus()
            val coreOk = !coreStatus.startsWith("native unavailable")

            val status = core.serverStatus()
            val running = status?.`running` ?: false
            // Prefer the live listen address; fall back to the configured one.
            val listenAddr = status?.`listenAddr` ?: settings.serverListenAddr
            serverRunning = running

            SwingUtilities.invokeLater {
                applyCoreStatus(coreOk, coreStatus)
                applyProxyStatus(running, listenAddr)
            }
        }
    }

    private fun applyCoreStatus(
        ok: Boolean,
        status: String,
    ) {
        if (ok) {
            paintDot(coreDot, Color(0x39, 0x9B, 0xD8)) // blue
            coreStatusLabel.text = status
            coreStatusLabel.foreground = labelFg
        } else {
            paintDot(coreDot, Color(0xE7, 0x4C, 0x3C)) // red
            coreStatusLabel.text = "unavailable"
            coreStatusLabel.foreground = Color(0xE7, 0x4C, 0x3C)
        }
    }

    private fun applyProxyStatus(
        running: Boolean,
        listenAddr: String,
    ) {
        if (running) {
            paintDot(proxyDot, Color(0x2E, 0xCC, 0x71)) // green
            proxyStatusLabel.text = "RUNNING on $listenAddr"
            proxyStatusLabel.foreground = labelFg
            startButton.isEnabled = false
            stopButton.isEnabled = true
        } else {
            paintDot(proxyDot, Color(0xE7, 0x4C, 0x3C)) // red
            proxyStatusLabel.text = "STOPPED"
            proxyStatusLabel.foreground = labelFg
            startButton.isEnabled = true
            stopButton.isEnabled = false
        }
    }

    // ── Output console helpers ──────────────────────────────────────────────

    private fun setOutput(message: String) {
        output.text = message
        output.caretPosition = 0
        log(message.lineSequence().firstOrNull() ?: "TLS+ action completed")
    }

    private fun appendOutput(message: String) {
        output.append("\n$message")
        output.caretPosition = output.document.length
        log(message)
    }

    private fun formatProxyResponse(r: ProxyResponse): String =
        buildString {
            if (r.`error` != null) {
                appendLine("✗ Proxy ERROR")
                appendLine(r.`error`)
                return@buildString
            }
            appendLine("Status:          ${r.`statusCode`}")
            appendLine("JA4 (outbound):  ${r.`ja4` ?: "n/a"}")
            appendLine("Headers:         ${r.`headers`.size}")
            appendLine()
            appendLine("── Headers ──")
            r.`headers`.take(15).forEach { appendLine("  $it") }
            if (r.`headers`.size > 15) appendLine("  … +${r.`headers`.size - 15} more")
            appendLine()
            appendLine("── Body (preview) ──")
            appendLine(r.`body`.toString(Charsets.UTF_8).take(2000))
        }

    // ── Theming utilities ─────────────────────────────────────────────────────

    private fun gbc(): GridBagConstraints =
        GridBagConstraints().apply {
            fill = GridBagConstraints.HORIZONTAL
            insets = Insets(8, 8, 8, 8)
            anchor = GridBagConstraints.WEST
            weightx = 1.0
        }

    private fun addLabeledRow(
        panel: JPanel,
        c: GridBagConstraints,
        row: Int,
        label: String,
        component: Component,
    ) {
        c.gridx = 0
        c.gridy = row
        c.gridwidth = 1
        c.weightx = 0.0
        panel.add(
            JLabel(label).apply {
                foreground = labelFg
                horizontalAlignment = SwingConstants.LEFT
            },
            c,
        )
        c.gridx = 1
        c.weightx = 1.0
        panel.add(component, c)
    }

    /**
     * A muted, word-wrapping hint.
     *
     * Burp disables HTML rendering in [JLabel] (the `<html>…` markup then shows
     * as literal text), so we use a read-only, transparent [JTextArea] which
     * word-wraps reliably under every look-and-feel. `maximumSize` is pinned to
     * the preferred height so the hint never stretches vertically inside a
     * `BoxLayout`.
     */
    private fun hintLabel(text: String): JComponent =
        object : JTextArea(text) {
            override fun getMaximumSize(): Dimension = Dimension(super.getMaximumSize().width, preferredSize.height)
        }.apply {
            isEditable = false
            isFocusable = false
            lineWrap = true
            wrapStyleWord = true
            isOpaque = false
            border = BorderFactory.createEmptyBorder(2, 0, 4, 0)
            foreground = lighten(labelFg, -0x22)
            font = font.deriveFont(font.size2D - 1f)
            alignmentX = LEFT_ALIGNMENT
        }

    private fun titled(title: String) =
        BorderFactory
            .createTitledBorder(
                BorderFactory.createLineBorder(lighten(panelBg, 0x18)),
                title,
            ).apply {
                titleColor = accent
            }

    private fun themedCheckBox(
        text: String,
        selected: Boolean,
    ): JCheckBox =
        JCheckBox(text, selected).apply {
            isOpaque = false
            foreground = labelFg
        }

    private fun themedField(
        text: String,
        cols: Int,
    ): JTextField =
        JTextField(text, cols).apply {
            background = inputBg
            foreground = inputFg
            caretColor = inputFg
            border =
                BorderFactory.createCompoundBorder(
                    BorderFactory.createLineBorder(lighten(panelBg, 0x18)),
                    BorderFactory.createEmptyBorder(3, 6, 3, 6),
                )
        }

    private fun themedCombo(items: Array<String>): JComboBox<String> =
        JComboBox(items).apply {
            background = inputBg
            foreground = inputFg
        }

    private fun statusDot(): JLabel =
        JLabel("●").apply {
            font = font.deriveFont(Font.BOLD, 13f)
            foreground = Color(0x80, 0x80, 0x80)
        }

    private fun paintDot(
        dot: JLabel,
        color: Color,
    ) {
        dot.foreground = color
    }

    /** Runs [block] on a daemon background thread, never on the EDT. */
    private fun runBackground(block: () -> Unit) {
        Thread {
            runCatching { block() }.onFailure { t ->
                SwingUtilities.invokeLater { appendOutput("Error: ${t.message}") }
            }
        }.apply {
            isDaemon = true
            name = "tlsplus-ui-worker"
            start()
        }
    }

    private fun uiColor(
        key: String,
        fallback: Color,
    ): Color = javax.swing.UIManager.getColor(key) ?: fallback

    /** Lightens (positive [delta]) or darkens (negative) a color per RGB channel. */
    private fun lighten(
        base: Color,
        delta: Int,
    ): Color {
        fun clamp(v: Int) = v.coerceIn(0, 255)
        return Color(
            clamp(base.red + delta),
            clamp(base.green + delta),
            clamp(base.blue + delta),
        )
    }

    private companion object {
        /** Live status poll interval (ms). Cheap, non-mutating serverStatus() query. */
        private const val STATUS_POLL_MS = 1800
    }
}
