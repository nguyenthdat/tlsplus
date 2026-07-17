---
name: burp-montoya-api
description: |
  Complete reference for the Burp Suite Montoya API (v2026.4) — all interfaces, classes, methods, and enums with Kotlin/Java usage patterns.
  Use when writing, reviewing, or debugging Burp Suite extensions in Kotlin or Java that use the Montoya API.
  Covers: BurpExtension, MontoyaApi, Proxy, HTTP, Scanner, UI, Logging, Sessions, WebSockets, Intruder, Repeater, Collaborator, Scope, Sitemap, Persistence, Utilities, AI, Bambdas, BChecks.
  Trigger keywords: Burp Suite extension, Montoya API, BurpExtension, MontoyaApi, ProxyHttpHandler, ProxyResponseHandler, ContextMenuItemsProvider, SessionHandlingAction, ScanCheck, ActiveScanCheck, WebSocket, Intruder, Repeater, Collaborator, Scope, audit.
---

# Burp Suite Montoya API Reference (v2026.4)

Comprehensive reference for the PortSwigger Montoya API. Official Javadoc: `https://portswigger.github.io/burp-extensions-montoya-api/javadoc/`

Official example repository: `https://github.com/PortSwigger/burp-extensions-montoya-api-examples`

---

## Extension Entry Point

Every extension implements `BurpExtension`:

**Kotlin:**
```kotlin
import burp.api.montoya.BurpExtension
import burp.api.montoya.MontoyaApi

@Suppress("unused")
class MyExtension : BurpExtension {
    override fun initialize(api: MontoyaApi) {
        api.extension().setName("My Extension")
        api.logging().logToOutput("Extension loaded.")
    }
}
```

**Java:**
```java
import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;

public class MyExtension implements BurpExtension {
    @Override
    public void initialize(MontoyaApi api) {
        api.extension().setName("My Extension");
        api.logging().logToOutput("Extension loaded.");
    }
}
```

---

## MontoyaApi — Root Interface Methods

| Method | Return Type | Description |
|--------|------------|-------------|
| `ai()` | `Ai` | [Pro] AI related functionality |
| `bambda()` | `Bambda` | Bambda functionality |
| `burpSuite()` | `BurpSuite` | Burp Suite application-level features |
| `collaborator()` | `Collaborator` | [Pro] Collaborator functionality |
| `comparer()` | `Comparer` | Comparer tool |
| `decoder()` | `Decoder` | Decoder tool |
| `extension()` | `Extension` | Extension metadata |
| `http()` | `Http` | HTTP requests/responses |
| `intruder()` | `Intruder` | Intruder tool |
| `logging()` | `Logging` | Logging and events |
| `organizer()` | `Organizer` | Organizer tool |
| `persistence()` | `Persistence` | Persistent storage |
| `project()` | `Project` | Project features |
| `proxy()` | `Proxy` | Proxy tool |
| `repeater()` | `Repeater` | Repeater tool |
| `scanner()` | `Scanner` | [Pro] Scanner tool |
| `scope()` | `Scope` | Suite-wide target scope |
| `siteMap()` | `SiteMap` | Site Map tool |
| `userInterface()` | `UserInterface` | UI functionality |
| `utilities()` | `Utilities` | Base64, JSON, HTML, URL utilities |
| `websockets()` | `WebSockets` | WebSocket functionality |

---

## Sub-Interface Method Reference

### Extension (`api.extension()`)

| Method | Description |
|--------|-------------|
| `setName(String)` | Set the extension display name |
| `name()` | Get the extension display name |
| `registerUnloadingHandler(ExtensionUnloadingHandler)` | Register handler called when extension is unloaded |
| `unload()` | Programmatically unload the extension |

---

### Logging (`api.logging()`)

| Method | Description |
|--------|-------------|
| `logToOutput(String)` | Log a message to the Output tab |
| `logToError(String)` | Log an error message |
| `raiseInfoEvent(String)` | Raise an info event in the event log |
| `raiseErrorEvent(String)` | Raise an error event |
| `raiseCriticalEvent(String)` | Raise a critical event |
| `logToOutput(String, ...)` | Formatted output logging |
| `logToError(String, ...)` | Formatted error logging |

---

### Proxy (`api.proxy()`)

| Method | Description |
|--------|-------------|
| `registerRequestHandler(ProxyRequestHandler)` | Register an HTTP request handler |
| `registerResponseHandler(ProxyResponseHandler)` | Register an HTTP response handler |
| `registerWebSocketCreationHandler(ProxyWebSocketCreationHandler)` | Register WebSocket creation handler |
| `history()` | Access proxy history — returns `ProxyHistoryFilter` chainable |
| `isInIntercept()` | Check if intercept is on |
| `enableIntercept()` | Enable intercept |
| `disableIntercept()` | Disable intercept |
| `interceptRequests()` | Access request intercept state |
| `interceptResponses()` | Access response intercept state |
| `intruderIntercept()` | Intruder intercept state |

#### Proxy History (`api.proxy().history()`)

| Method | Description |
|--------|-------------|
| `withUrlPrefix(String)` | Filter by URL prefix |
| `withAnnotation(String)` | Filter by annotation text |
| `withHighlight(HighlightColor)` | Filter by highlight color |
| `withRequestContent(String)` | Filter by request content |
| `withResponseContent(String)` | Filter by response content |
| `withStatusCode(int)` | Filter by status code |
| `withStatusClass(int)` | Filter by status code class |
| `withMimeType(MimeType)` | Filter by MIME type |
| `withToolFlag(ToolFlag)` | Filter by tool flag |
| `withListenerInterface(String)` | Filter by listener interface |
| `withComment(String)` | Filter by comment |
| `results()` | Get filtered results as `List<ProxyHttpRequestResponse>` |
| `reset()` | Reset all filters |

---

### Http (`api.http()`)

| Method | Description |
|--------|-------------|
| `registerHttpHandler(HttpHandler)` | Register HTTP handler (pre-request, post-response) |
| `registerSessionHandlingAction(SessionHandlingAction)` | Register session handling action |
| `sendRequest(HttpRequest)` | Send an HTTP request |
| `sendRequest(HttpRequest, HttpMode)` | Send with HTTP mode |
| `sendRequest(HttpRequest, HttpMode, String)` | Send with mode and connection ID |
| `sendRequests(List<HttpRequest>)` | Send multiple requests |
| `createRequest(HttpService, String)` | Create a request from string |
| `createRequest(HttpService, byte[])` | Create a request from raw bytes |
| `createResponse(String)` | Create a response from string |
| `createResponse(byte[])` | Create a response from raw bytes |
| `createRequestFromUrl(String)` | Create a GET request from URL |
| `requestToHeader(HttpRequest)` | Convert request to header string |
| `responseToHeader(HttpResponse)` | Convert response to header string |

#### HttpService (for `createRequest` / `createRequestFromUrl`)

| Static Method | Description |
|---------------|-------------|
| `HttpService.httpService(String)` | Create HttpService from URL string |
| `HttpService.httpService(String, int, boolean)` | Create with host, port, TLS flag |
| `HttpService.httpService(HttpService, HttpProtocol)` | Clone with different protocol |

---

### Proxy HTTP Handlers

#### ProxyRequestHandler

```kotlin
import burp.api.montoya.proxy.http.ProxyRequestHandler
import burp.api.montoya.proxy.http.ProxyRequestReceivedAction
import burp.api.montoya.proxy.http.ProxyRequestToBeSentAction
import burp.api.montoya.proxy.http.InterceptedRequest

class MyRequestHandler : ProxyRequestHandler {
    override fun handleRequestReceived(request: InterceptedRequest): ProxyRequestReceivedAction {
        // Modify request before rules/scripts apply
        return ProxyRequestReceivedAction.continueWith(request)
        // OR: ProxyRequestReceivedAction.drop()
        // OR: ProxyRequestReceivedAction.doNotIntercept(request)
        // OR: ProxyRequestReceivedAction.intercept(request)
    }

    override fun handleRequestToBeSent(request: InterceptedRequest): ProxyRequestToBeSentAction {
        // Modify request after rules/scripts, before sending
        return ProxyRequestToBeSentAction.continueWith(request)
    }
}
```

#### ProxyResponseHandler

```kotlin
import burp.api.montoya.proxy.http.ProxyResponseHandler
import burp.api.montoya.proxy.http.ProxyResponseReceivedAction
import burp.api.montoya.proxy.http.ProxyResponseToBeSentAction
import burp.api.montoya.proxy.http.InterceptedResponse

class MyResponseHandler(private val api: MontoyaApi) : ProxyResponseHandler {
    override fun handleResponseReceived(response: InterceptedResponse): ProxyResponseReceivedAction {
        // Modify response before rules/scripts apply
        val annotations = Annotations.annotations("Modified", HighlightColor.ORANGE)
        return ProxyResponseReceivedAction.continueWith(response, annotations)
    }

    override fun handleResponseToBeSent(response: InterceptedResponse): ProxyResponseToBeSentAction {
        return ProxyResponseToBeSentAction.continueWith(response)
    }
}
```

**Action static methods:**

| Action Class | Static Methods |
|-------------|----------------|
| `ProxyRequestReceivedAction` | `continueWith(InterceptedRequest)`, `continueWith(InterceptedRequest, Annotations)`, `drop()`, `doNotIntercept(InterceptedRequest)`, `intercept(InterceptedRequest)` |
| `ProxyRequestToBeSentAction` | `continueWith(InterceptedRequest)`, `continueWith(InterceptedRequest, Annotations)`, `drop()` |
| `ProxyResponseReceivedAction` | `continueWith(InterceptedResponse)`, `continueWith(InterceptedResponse, Annotations)`, `drop()`, `doNotIntercept(InterceptedResponse)`, `intercept(InterceptedResponse)` |
| `ProxyResponseToBeSentAction` | `continueWith(InterceptedResponse)`, `continueWith(InterceptedResponse, Annotations)`, `drop()` |

#### InterceptedRequest / InterceptedResponse

**InterceptedRequest methods:**
- `request()` → `HttpRequest`
- `messageInfo()` → `InterceptedHttpMessage`
- `annotations()` → `Annotations`
- `listenerInterface()` → `String`
- `contentType()` → `ContentType`
- `httpService()` → `HttpService`
- `time()` → `ZonedDateTime`
- `toolSource()` → `ToolSource`

**InterceptedResponse methods:**
- `requestResponse()` → `HttpRequestResponse` (use `.request()` / `.response()` on it)
- `messageInfo()` → `InterceptedHttpMessage`
- `annotations()` → `Annotations`
- `inferredMimeType()` → `MimeType`
- `statedMimeType()` → `MimeType`
- `body()` → `byte[]`
- `bodyToString()` → `String`
- `bodyOffset()` → `int`
- `headers()` → `HttpHeaders`
- `statusCode()` → `short`
- `reasonPhrase()` → `String`
- `httpService()` → `HttpService`
- `attributes(AttributeType...)` → `List<Attribute>`

---

### HTTP Handler (`api.http().registerHttpHandler`)

```kotlin
import burp.api.montoya.http.handler.HttpHandler
import burp.api.montoya.http.handler.RequestToBeSentAction
import burp.api.montoya.http.handler.ResponseReceivedAction
import burp.api.montoya.http.handler.HttpRequestToBeSent
import burp.api.montoya.http.handler.HttpResponseReceived

class MyHttpHandler : HttpHandler {
    override fun handleHttpRequestToBeSent(request: HttpRequestToBeSent): RequestToBeSentAction {
        // Runs for ALL tools (Proxy, Repeater, Scanner, etc.)
        return RequestToBeSentAction.continueWith(request)
    }

    override fun handleHttpResponseReceived(response: HttpResponseReceived): ResponseReceivedAction {
        return ResponseReceivedAction.continueWith(response)
    }
}
```

**Action static methods:**
- `RequestToBeSentAction.continueWith(HttpRequestToBeSent)`, `continueWith(HttpRequestToBeSent, Annotations)`, `continueWith(HttpRequest)`
- `ResponseReceivedAction.continueWith(HttpResponseReceived)`, `continueWith(HttpResponseReceived, Annotations)`

---

### Session Handling (`api.http().registerSessionHandlingAction`)

```kotlin
import burp.api.montoya.http.sessions.SessionHandlingAction
import burp.api.montoya.http.sessions.SessionHandlingActionData
import burp.api.montoya.http.sessions.ActionResult

class MySessionHandler : SessionHandlingAction {
    override fun performAction(data: SessionHandlingActionData): ActionResult {
        val request = data.request()
        val macros = data.macros() // List<HttpRequestResponse>
        val annotations = data.annotations()

        // Modify request, e.g. update auth token
        val modifiedRequest = request.withHeader("Authorization", "Bearer new-token")
        return ActionResult.actionResult(modifiedRequest, annotations)
    }
}
```

`ActionResult` has static factory methods: `actionResult(HttpRequest)`, `actionResult(HttpRequest, Annotations)`

---

### Scanner (`api.scanner()`)

| Method | Description |
|--------|-------------|
| `registerScanCheck(ScanCheck)` | Register a scan check (legacy) |
| `registerActiveScanCheck(ActiveScanCheck, ScanCheckType)` | Register an active scan check |
| `registerInsertionPointProvider(AuditInsertionPointProvider)` | Register custom insertion points |
| `registerAuditIssueHandler(AuditIssueHandler)` | Register audit issue handler |
| `startAudit(AuditConfiguration)` | Start an audit — returns `Audit` |
| `doActiveScan(HttpService, byte[], List<AuditInsertionPoint>)` | Active scan — returns `AuditResult` |
| `doPassiveScan(HttpRequestResponse)` | Passive scan — returns `AuditResult` |
| `bChecks()` | Access BChecks |

#### Audit

| Method | Description |
|--------|-------------|
| `addRequest(HttpRequest)` | Add request to audit |
| `addRequest(HttpRequest, List<Range>)` | Add request with insertion point ranges |
| `addRequestResponse(HttpRequestResponse)` | Add request/response pair |
| `isFinished()` | Check if audit completed |
| `cancel()` | Cancel the audit |
| `numberOfRequests()` | Number of requests audited |
| `numberOfAuditItems()` | Number of audit items |
| `status()` | Current audit status |
| `delete()` | Delete the audit |

---

### UI (`api.userInterface()`)

| Method | Description |
|--------|-------------|
| `registerContextMenuItemsProvider(ContextMenuItemsProvider)` | Register right-click context menu |
| `registerSuiteTab(String, Component)` | Add a custom tab to Burp UI |
| `registerHttpRequestEditorProvider(HttpRequestEditorProvider)` | Custom HTTP request editor |
| `registerHttpResponseEditorProvider(HttpResponseEditorProvider)` | Custom HTTP response editor |
| `registerWebSocketMessageEditorProvider(WebSocketMessageEditorProvider)` | Custom WebSocket editor |
| `registerHotkey(Hotkey)` | Register global hotkey |
| `registerContextMenuItemsProvider(InvocationType, ContextMenuItemsProvider)` | Context menu filter by invocation type |
| `menuBar()` | Access top menu bar |
| `applyThemeToComponent(Component)` | Apply Burp theme to Swing component |
| `currentDisplayMode()` | Current display mode (LIGHT/DARK) |
| `fontSize()` | Current font size |
| `swingUtils()` | Swing UI utilities |
| `isInExpertMode()` | Expert mode state |

#### Context Menu Items

```kotlin
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider
import burp.api.montoya.ui.contextmenu.ContextMenuEvent
import javax.swing.JMenuItem

class MyContextMenu : ContextMenuItemsProvider {
    override fun provideMenuItems(event: ContextMenuEvent): List<Component> {
        val menuItem = JMenuItem("My Action")
        menuItem.addActionListener {
            // Handle context menu click
            val selectedMessages = event.selectedRequestResponses()
            // ...
        }
        return listOf(menuItem)
    }
}
```

**ContextMenuEvent — available on event:**
- `selectedRequestResponses()` → `List<HttpRequestResponse>`
- `invocationType()` → `InvocationType`
- `isFrom(InvocationType...)` → `boolean`
- `messageEditorHttpRequestResponse()` → `Optional<HttpRequestResponse>`
- `selectionBounds()` → `SelectionBounds`
- `selectedIssues()` → `List<AuditIssue>`
- `toolSource()` → `ToolSource`

**InvocationType enum:** `PROXY_HISTORY`, `SITE_MAP`, `SCANNER_RESULTS`, `TARGET`, `INTRUDER`, `REPEATER`, `LOGGER`, `WEB_SOCKETS`, `ORGANIZER`, `SEARCH_RESULTS`, `MESSAGE_EDITOR_REQUEST`, `MESSAGE_EDITOR_RESPONSE`, `MESSAGE_VIEWER_REQUEST`, `MESSAGE_VIEWER_RESPONSE`

#### Suite Tab

```kotlin
val panel = JPanel()
panel.add(JLabel("Hello World"))
api.userInterface().registerSuiteTab("My Tab", panel)
```

---

### Logger (`api.logging()` + Burp's logger)

Access via `Http`:
- `api.http().logger()` — logger functionality

---

### Intruder (`api.intruder()`)

| Method | Description |
|--------|-------------|
| `registerPayloadProcessor(IntruderPayloadProcessor)` | Register custom payload processor |
| `registerPayloadGeneratorProvider(IntruderPayloadGeneratorProvider)` | Register custom payload generator |
| `sendToIntruder(HttpService, HttpRequest)` | Send request to Intruder |
| `sendToIntruder(HttpService, HttpRequest, String, List<IntruderInsertionPoint>)` | Send with insertion points |
| `sendToIntruder(HttpService, byte[], List<IntruderInsertionPoint>)` | Send raw bytes |

**IntruderPayloadGeneratorProvider:**
```kotlin
class MyPayloadProvider : IntruderPayloadGeneratorProvider {
    override fun displayName(): String = "My Generator"
    override fun providePayloads(attack: Attack): IntruderPayloadGenerator {
        return MyPayloadGenerator()
    }
}
```

---

### Repeater (`api.repeater()`)

| Method | Description |
|--------|-------------|
| `sendToRepeater(HttpService, HttpRequest)` | Send request to Repeater |
| `sendToRepeater(HttpService, HttpRequest, String)` | Send with tab name |
| `sendToRepeater(HttpService, byte[])` | Send raw bytes |
| `sendToRepeater(HttpService, byte[], String)` | Send raw bytes with tab name |
| `addTab(String)` | Add empty tab |

---

### WebSockets (`api.websockets()`)

| Method | Description |
|--------|-------------|
| `registerWebSocketCreatedHandler(WebSocketCreatedHandler)` | Register handler for WebSocket creation |

**Proxy WebSocket Handlers (via `api.proxy()`):**
- `registerWebSocketCreationHandler(ProxyWebSocketCreationHandler)`

```kotlin
class MyWsHandler : ProxyWebSocketCreationHandler {
    override fun handleWebSocketCreation(creation: ProxyWebSocketCreation) {
        creation.proxyWebSocket().registerProxyMessageHandler(object : ProxyWebSocketMessageHandler {
            override fun handleTextMessageReceived(textMessage: InterceptedTextMessage): TextMessageReceivedAction {
                val modified = textMessage.withPayload("modified")
                return TextMessageReceivedAction.continueWith(modified)
            }
            override fun handleTextMessageToBeSent(textMessage: InterceptedTextMessage): TextMessageToBeSentAction {
                return TextMessageToBeSentAction.continueWith(textMessage)
            }
            override fun handleBinaryMessageReceived(msg: InterceptedBinaryMessage): BinaryMessageReceivedAction {
                return BinaryMessageReceivedAction.continueWith(msg)
            }
            override fun handleBinaryMessageToBeSent(msg: InterceptedBinaryMessage): BinaryMessageToBeSentAction {
                return BinaryMessageToBeSentAction.continueWith(msg)
            }
        })
    }
}
```

---

### Collaborator (`api.collaborator()`)

| Method | Description |
|--------|-------------|
| `createPayload()` | Create a Collaborator payload — returns `CollaboratorPayload` |
| `generatePayload(boolean)` | Generate payload with/without private IP |
| `getAllInteractionsFor(CollaboratorPayload)` | Get all interactions |
| `getInteractionsSince(CollaboratorPayload, ZonedDateTime)` | Get interactions since time |
| `getAllServers()` | List Collaborator servers |

---

### Scope (`api.scope()`)

| Method | Description |
|--------|-------------|
| `isInScope(String)` | Check if URL is in scope |
| `isInScope(HttpService)` | Check if HttpService is in scope |
| `includeInScope(String)` | Add URL to scope |
| `excludeFromScope(String)` | Exclude URL from scope |
| `scopeItems()` | List scope items |
| `exclusions()` | List exclusions |

---

### SiteMap (`api.siteMap()`)

| Method | Description |
|--------|-------------|
| `add(HttpRequestResponse)` | Add to site map |
| `add(AuditIssue)` | Register audit issue |
| `requestResponses()` | All items in site map |
| `requestResponses(String)` | Filter by URL prefix |
| `requestResponses(HttpService)` | Filter by service |

---

### Persistence (`api.persistence()`)

| Method | Description |
|--------|-------------|
| `preferences()` | Access `Preferences` for key-value storage |
| `extensionData()` | Access `ExtensionData` for file-based storage |

**Preferences:**
- `setString(String key, String value)`
- `getString(String key)` → `String?`
- `setBoolean(String key, boolean value)`
- `getBoolean(String key)` → `Boolean?`
- `setInteger(String key, int value)`
- `getInteger(String key)` → `Integer?`
- `delete(String key)`
- `keys()` → `Set<String>`

---

### Utilities (`api.utilities()`)

| Sub-interface | Accessor |
|--------------|----------|
| `Base64Utils` | `api.utilities().base64Utils()` — encode/decode with options |
| `JsonUtils` | `api.utilities().jsonUtils()` — parse, set, add JSON |
| `HtmlUtils` | `api.utilities().htmlUtils()` — encode/decode HTML |
| `URLUtils` | `api.utilities().urlUtils()` — encode/decode URLs |
| `RandomUtils` | `api.utilities().randomUtils()` — random strings/bytes |
| `RankUtils` | `api.utilities().rankUtils()` — rank responses |
| `ShellUtils` | `api.utilities().shellUtils()` — execute shell commands |
| `ByteUtils` | `api.utilities().byteUtils()` — byte array utilities |
| `StringUtils` | `api.utilities().stringUtils()` — string manupulation |
| `NumberUtils` | `api.utilities().numberUtils()` — number utilities |
| `CRC32ChecksumUtils` | `api.utilities().crc32ChecksumUtils()` |

**Base64Utils:**
- `encode(byte[])`, `encode(String)` → `String`
- `decode(String)`, `decode(byte[])` → `byte[]`
- `encode(byte[], Base64EncodingOptions...)`, `decode(String, Base64DecodingOptions...)`

**JsonUtils:**
- `parse(String)` → `JsonNode`
- `set(String sourceJson, String location, String newValue)` → `String`
- `add(String sourceJson, String location, String newJson)` → `String`
- `remove(String sourceJson, String location)` → `String`

**HtmlUtils:**
- `encode(String, HtmlEncoding)` → `String`
- `decode(String)` → `String`

**URLUtils:**
- `encode(String, URLEncoding)` → `String`
- `decode(String)` → `String`

**RandomUtils:**
- `randomString(int, CharacterSet...)` → `String`
- `randomBytes(int)` → `byte[]`
- `randomInt(int)` → `int`
- `randomInt(int, int)` → `int`
- `CharacterSet`: `ASCII_LETTERS`, `ASCII_LOWERCASE`, `ASCII_UPPERCASE`, `DIGITS`, `PUNCTUATION`

**ShellUtils:**
- `execute(ShellCommand)` → `ShellResult`
- `execute(String)` → `ShellResult`
- `ShellCommand`: `.shellCommand(String)`, `.withWorkingDirectory(Path)`, `.withTimeout(Duration)`, `.withTimeoutBehavior(TimeoutBehavior)`, `.withExitCodeBehavior(ExitCodeBehavior)`

---

### Ai (`api.ai()`)

| Method | Description |
|--------|-------------|
| `prompt()` | Send a prompt — returns `AiPromptResponse` |
| `chat()` | Start a chat session — returns `AiChat` |
| `isEnabled()` | Check if AI is available |
| `availableModels()` | List available models |

**Chat usage:**
```kotlin
val chat = api.ai().chat()
val response = chat.sendMessage(
    Message.userMessage("Analyze this request"),
    Message.userMessage(request.toString())
)
```

---

### Bambda (`api.bambda()`)

| Method | Description |
|--------|-------------|
| `importBambda(String url, String name)` | Import Bambda from URL |
| `importBambda(Path path, String name)` | Import from file |
| `importedBambdas()` | List imported Bambdas |

---

### EnhancedCapability

Override in your extension class:

```kotlin
override fun enhancedCapabilities(): Set<EnhancedCapability> {
    return setOf(EnhancedCapability.AI_FEATURES)
}
```

**Values:** `AI_FEATURES`

---

## Core Data Classes

### HttpRequest (`api.http().createRequest(...)` or from intercepted)

| Method | Description |
|--------|-------------|
| `method()` | HTTP method |
| `path()` | Request path |
| `pathWithoutQuery()` | Path without query string |
| `query()` | Query string |
| `url()` | Full URL |
| `httpService()` | Target HttpService |
| `headers()` | HttpHeaders |
| `body()` | Request body bytes |
| `bodyToString()` | Body as string |
| `bodyOffset()` | Body offset in raw bytes |
| `contentType()` | ContentType enum |
| `parameters()` | List of `HttpParameter` |
| `markers()` | Highlight markers |
| `httpVersion()` | HTTP version string |
| `httpProtocol()` | HTTP/1 vs HTTP/2 |
| `toByteArray()` | Raw request bytes |
| `toString()` | Request as string |
| `withService(HttpService)` | Clone with different service |
| `withMethod(String)` | Clone with different method |
| `withPath(String)` | Clone with different path |
| `withHeader(String, String)` | Clone with added/updated header |
| `withHeader(HttpHeader)` | Clone with header |
| `withRemovedHeader(String)` | Clone with header removed |
| `withAddedParameters(List<HttpParameter>)` | Clone with added parameters |
| `withRemovedParameters(List<HttpParameter>)` | Clone with removed parameters |
| `withUpdatedParameters(List<HttpParameter>)` | Clone with updated parameters |
| `withBody(String)` | Clone with body string |
| `withBody(byte[])` | Clone with body bytes |
| `withAddedMarkers(List<Marker>)` | Clone with markers |

**Static factory:**
- `HttpRequest.httpRequest(HttpService, String)` — from string
- `HttpRequest.httpRequest(HttpService, byte[])` — from bytes
- `HttpRequest.httpRequestFromUrl(String)` — GET from URL

### HttpResponse

| Method | Description |
|--------|-------------|
| `statusCode()` | HTTP status code |
| `reasonPhrase()` | Status reason phrase |
| `headers()` | HttpHeaders |
| `body()` | Response body bytes |
| `bodyToString()` | Body as string |
| `bodyOffset()` | Body offset |
| `httpVersion()` | HTTP version |
| `statedMimeType()` | Content-Type MIME type |
| `inferredMimeType()` | Inferred MIME type |
| `httpService()` | Target service |
| `attributes(AttributeType...)` | Response attributes |
| `toByteArray()` | Raw response bytes |
| `toString()` | Response as string |
| `withStatusCode(short)` | Clone with different status code |
| `withReasonPhrase(String)` | Clone with different reason phrase |
| `withHeader(String, String)` | Clone with header |
| `withBody(String)` | Clone with body |
| `withBody(byte[])` | Clone with body bytes |

**Static factory:**
- `HttpResponse.httpResponse(String)` — from string
- `HttpResponse.httpResponse(byte[])` — from bytes

### HttpRequestResponse

Combines request and response. Key methods:
- `request()` → `HttpRequest`
- `response()` → `HttpResponse` (nullable)
- `url()` → `String`
- `httpService()` → `HttpService`
- `annotations()` → `Annotations`
- `hasResponse()` → `boolean`
- `requestResponse()` → `HttpRequestResponse`

### HttpHeaders

- `header(String name)` → `HttpHeader?`
- `headerValue(String name)` → `String?`
- `hasHeader(String name)` → `boolean`
- `hasHeader(String name, String value)` → `boolean`
- `contains(String name)` → `boolean`

### HttpParameter

| Method | Description |
|--------|-------------|
| `type()` | `HttpParameterType` (URL, BODY, COOKIE, XML, JSON, MULTIPART_ATTR, etc.) |
| `name()` | Parameter name |
| `value()` | Parameter value |
| `nameStart()` | Start offset |
| `nameEnd()` | End offset of name |
| `valueStart()` | Start offset of value |
| `valueEnd()` | End offset of value |

### Annotations

Static factory: `Annotations.annotations()`, `Annotations.annotations(HighlightColor)`, `Annotations.annotations(String)`, `Annotations.annotations(String, HighlightColor)`

Usage: create via `Annotations` static methods, pass to action `.continueWith()` methods.

### HighlightColor

`RED`, `ORANGE`, `YELLOW`, `GREEN`, `CYAN`, `BLUE`, `PINK`, `MAGENTA`, `GRAY`, `NONE`

### MimeType

`NONE`, `AMBIGUOUS`, `HTML`, `JSON`, `XML`, `CSS`, `SCRIPT`, `IMAGE_UNKNOWN`, `IMAGE_JPEG`, `IMAGE_GIF`, `IMAGE_PNG`, `IMAGE_BMP`, `IMAGE_TIFF`, `APPLICATION_FLASH`, `APPLICATION_UNKNOWN`, `SOUND`, `VIDEO`, `FONT_WOFF`, `FONT_WOFF2`

### ContentType

`NONE`, `AMF`, `JSON`, `XML`, `URL_ENCODED`, `MULTIPART`, `UNRECOGNIZED`

### ByteRange

`ByteRange.byteRange(int start, int end)` — represents a byte range for markers/insertion points.

### Marker

`Marker.marker(String expression, ByteRange)` — for highlight markers in HTTP messages.

---

## Proxy WebSocket API

### ProxyWebSocket

| Method | Description |
|--------|-------------|
| `registerProxyMessageHandler(ProxyWebSocketMessageHandler)` | Register message handler |
| `upgradeRequestResponse()` | HTTP upgrade handshake |
| `sendTextMessage(String)` | Send text message |
| `sendBinaryMessage(byte[])` | Send binary message |
| `close()` | Close connection |
| `isOpen()` | Check if open |
| `id()` | Connection ID |

### ProxyWebSocketMessage Actions

**TextMessageReceivedAction / TextMessageToBeSentAction:**
- `continueWith(InterceptedTextMessage)` — pass through
- `continueWith(InterceptedTextMessage, Annotations)` — pass with annotations
- `drop()` — drop message

**BinaryMessageReceivedAction / BinaryMessageToBeSentAction:**
- `continueWith(InterceptedBinaryMessage)` — pass through
- `continueWith(InterceptedBinaryMessage, Annotations)` — pass with annotations
- `drop()` — drop message

---

## Intruder Payload API

### IntruderPayloadGenerator

```kotlin
class MyPayloadGenerator : IntruderPayloadGenerator {
    override fun hasMorePayloads(): Boolean = ...
    override fun nextPayload(baseValue: ByteArray): ByteArray = ...
    override fun reset() { ... }
}
```

### IntruderPayloadProcessor

```kotlin
class MyPayloadProcessor : IntruderPayloadProcessor {
    override fun displayName(): String = "My Processor"
    override fun processPayload(currentPayload: ByteArray, originalPayload: ByteArray, baseValue: ByteArray): ByteArray = ...
}
```

---

## Scanner Check API

### ActiveScanCheck

```kotlin
class MyActiveScanCheck : ActiveScanCheck {
    override fun activeAudit(baseRequestResponse: HttpRequestResponse, insertionPoint: AuditInsertionPoint): List<AuditIssue> {
        // Build and send probe requests, check responses
        val probe = insertionPoint.buildRequest("' OR 1=1 --")
        val response = /* send probe via api.http().sendRequest(probe) */
        // Return audit issues if vulnerabilities found
        return emptyList()
    }
}
```

### ScanCheck (legacy)

```kotlin
class MyScanCheck : ScanCheck {
    override fun activeAudit(baseRequestResponse: HttpRequestResponse, insertionPoint: AuditInsertionPoint): List<AuditIssue> = emptyList()
    override fun passiveAudit(baseRequestResponse: HttpRequestResponse): List<AuditIssue> = emptyList()
    override fun consolidateDuplicateIssues(newIssue: AuditIssue, existingIssue: AuditIssue): AuditIssueConsolidationAction { ... }
}
```

---

## Settings API (`api.userInterface().registerSettingsPanel`)

```kotlin
import burp.api.montoya.ui.settings.SettingsPanelBuilder
import burp.api.montoya.ui.settings.SettingsPanelPersistence
import burp.api.montoya.ui.settings.SettingsPanelSetting

val settingsPanel = SettingsPanelBuilder.settingsPanel()
    .withTitle("My Extension")
    .withDescription("Extension configuration.")
    .withPersistence(SettingsPanelPersistence.PROJECT_SETTINGS)
    .withSetting(SettingsPanelSetting.booleanSetting("Enable feature", true))
    .withSetting(SettingsPanelSetting.stringSetting("API key", ""))
    .withSetting(SettingsPanelSetting.integerSetting("Timeout seconds", 30))
    .withKeywords("my-extension", "proxy")
    .build()

api.userInterface().registerSettingsPanel(settingsPanel)

val enabled = settingsPanel.getBoolean("Enable feature")
val apiKey = settingsPanel.getString("API key")
val timeout = settingsPanel.getInteger("Timeout seconds")
```

---

## Editor API (`api.userInterface().registerHttpRequestEditorProvider`)

```kotlin
class MyRequestEditorProvider : HttpRequestEditorProvider {
    override fun provideHttpRequestEditor(request: HttpRequest): HttpRequestEditor {
        return object : HttpRequestEditor {
            override fun uiComponent(): Component = ...
            override fun isModified(): Boolean = ...
            override fun getRequest(): HttpRequest = ...
            override fun setRequest(request: HttpRequest) { ... }
            override fun selectionBounds(): SelectionBounds? = ...
            override fun canAcceptSelection(): Boolean = ...
            override fun caption(): String = "My Editor"
        }
    }
}
```

---

## GitHub Example Repositories

### Official PortSwigger Examples
- **`PortSwigger/burp-extensions-montoya-api-examples`** — Official Java examples for all API features
- **`PortSwigger/burp-extensions-montoya-api`** — The API source itself

### Kotlin Examples
- **`ncoblentz/KotlinBurpExtensionBase`** — Complete Kotlin project template with Gradle, ShadowJar
- **`ncoblentz/KotlinBurpJwtTokenHandlerDemo`** — JWT token handling with SessionHandlingAction
- **`ncoblentz/KotlinBurpAutoNameRepeaterTab`** — ContextMenuItemsProvider + Repeater integration
- **`VirtueSecurity/VirtueBurpPowerTools`** — Match/replace session handler in Kotlin
- **`penpard/penpard`** — Modern Kotlin extension with MCP server integration

### Java Examples
- **`Tib3rius/Collector`** — HTTP response handler, session handling
- **`Jaysen13/jaysenwxapkg`** — Extension structure example
- **`shiomiyan/burp-http-history-highlighter`** — Logger/history manipulation

### Gradle Build Pattern (Kotlin Extension)

```kotlin
// build.gradle.kts
plugins {
    kotlin("jvm") version "1.9.22"
    id("com.gradleup.shadow") version "8.3.0"
}

group = "com.example"
version = "1.0.0"

repositories {
    mavenCentral()
}

dependencies {
    compileOnly("net.portswigger.burp.extensions:montoya-api:2026.4")
}

tasks.shadowJar {
    archiveClassifier.set("all")
}

tasks.jar {
    manifest {
        attributes(
            "Main-Class" to "burp.MyExtension"
        )
    }
}
```

### Maven Dependency

```xml
<dependency>
    <groupId>net.portswigger.burp.extensions</groupId>
    <artifactId>montoya-api</artifactId>
    <version>2026.4</version>
    <scope>provided</scope>
</dependency>
```

---

## Common Patterns

### Pattern 1: Simple Extension with Context Menu

```kotlin
class MyExtension : BurpExtension {
    override fun initialize(api: MontoyaApi) {
        api.extension().setName("My Extension")
        api.userInterface().registerContextMenuItemsProvider(MyContextMenu(api))
    }
}

class MyContextMenu(private val api: MontoyaApi) : ContextMenuItemsProvider {
    override fun provideMenuItems(event: ContextMenuEvent): List<Component> {
        val item = JMenuItem("Process with My Extension")
        item.addActionListener {
            val responses = event.selectedRequestResponses()
            for (rr in responses) {
                api.logging().logToOutput("Selected: ${rr.url()}")
            }
        }
        return listOf(item)
    }
}
```

### Pattern 2: Proxy Response Handler with Annotations

```kotlin
class MyExtension : BurpExtension {
    override fun initialize(api: MontoyaApi) {
        api.extension().setName("Response Analyzer")
        api.proxy().registerResponseHandler(AnalyzerResponseHandler(api))
    }
}

class AnalyzerResponseHandler(private val api: MontoyaApi) : ProxyResponseHandler {
    override fun handleResponseReceived(response: InterceptedResponse): ProxyResponseReceivedAction {
        val body = response.bodyToString()
        if (body.contains("secret-key")) {
            val annotations = Annotations.annotations("Found secret key!", HighlightColor.RED)
            return ProxyResponseReceivedAction.continueWith(response, annotations)
        }
        return ProxyResponseReceivedAction.continueWith(response)
    }

    override fun handleResponseToBeSent(response: InterceptedResponse): ProxyResponseToBeSentAction {
        return ProxyResponseToBeSentAction.continueWith(response)
    }
}
```

### Pattern 3: Session Handling (JWT/Auth Token Refresh)

```kotlin
class MyExtension : BurpExtension {
    override fun initialize(api: MontoyaApi) {
        api.extension().setName("Auth Token Refresher")
        api.http().registerSessionHandlingAction(TokenRefreshHandler(api))
    }
}

class TokenRefreshHandler(private val api: MontoyaApi) : SessionHandlingAction {
    override fun performAction(data: SessionHandlingActionData): ActionResult {
        val request = data.request()
        val newToken = fetchNewToken()
        val modifiedRequest = request.withHeader("Authorization", "Bearer $newToken")
        api.logging().logToOutput("Refreshed token for: ${request.url()}")
        return ActionResult.actionResult(modifiedRequest, data.annotations())
    }

    private fun fetchNewToken(): String {
        // Your token refresh logic
        return "new-token-value"
    }
}
```

### Pattern 4: Custom Scanner Check

```kotlin
class MyExtension : BurpExtension {
    override fun initialize(api: MontoyaApi) {
        api.extension().setName("Custom Scanner")
        api.scanner().registerActiveScanCheck(MyScanCheck(api), ScanCheckType.EXTENSION_PROVIDED)
    }
}

class MyScanCheck(private val api: MontoyaApi) : ActiveScanCheck {
    override fun activeAudit(
        baseRequestResponse: HttpRequestResponse,
        insertionPoint: AuditInsertionPoint
    ): List<AuditIssue> {
        val probeRequest = insertionPoint.buildRequest("PAYLOAD")
        val probeResponse = api.http().sendRequest(probeRequest)

        if (probeResponse.response()?.bodyToString()?.contains("vulnerable") == true) {
            val issue = AuditIssue.auditIssue(
                "Custom Vulnerability Found",
                "Detailed description",
                "Remediation advice",
                probeRequest.url(),
                AuditIssueSeverity.HIGH,
                AuditIssueConfidence.CERTAIN,
                "Background info",
                "Remediation details",
                AuditIssueSeverity.HIGH,
                listOf(probeResponse)
            )
            return listOf(issue)
        }
        return emptyList()
    }
}
```

### Pattern 5: WebSocket Handler

```kotlin
class MyExtension : BurpExtension {
    override fun initialize(api: MontoyaApi) {
        api.extension().setName("WebSocket Logger")
        api.proxy().registerWebSocketCreationHandler(MyWsLogger(api))
    }
}

class MyWsLogger(private val api: MontoyaApi) : ProxyWebSocketCreationHandler {
    override fun handleWebSocketCreation(creation: ProxyWebSocketCreation) {
        creation.proxyWebSocket().registerProxyMessageHandler(object : ProxyWebSocketMessageHandler {
            override fun handleTextMessageReceived(msg: InterceptedTextMessage): TextMessageReceivedAction {
                api.logging().logToOutput("WS Received: ${msg.payload()}")
                return TextMessageReceivedAction.continueWith(msg)
            }
            override fun handleTextMessageToBeSent(msg: InterceptedTextMessage): TextMessageToBeSentAction {
                api.logging().logToOutput("WS Sent: ${msg.payload()}")
                return TextMessageToBeSentAction.continueWith(msg)
            }
            override fun handleBinaryMessageReceived(msg: InterceptedBinaryMessage): BinaryMessageReceivedAction {
                return BinaryMessageReceivedAction.continueWith(msg)
            }
            override fun handleBinaryMessageToBeSent(msg: InterceptedBinaryMessage): BinaryMessageToBeSentAction {
                return BinaryMessageToBeSentAction.continueWith(msg)
            }
        })
    }
}
```
