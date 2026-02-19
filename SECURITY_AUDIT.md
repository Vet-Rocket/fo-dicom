# fo-dicom Security Audit Report

## Scope

This report covers the `Vet-Rocket/fo-dicom` codebase, focusing on the network stack
(`DICOM/Network/`), protocol parsing (`PDU.cs`), file I/O (`DICOM/IO/`), and related
supporting code. All findings are presented with sufficient detail for developers to
reproduce and fix each issue.

---

## Findings

### FINDING-01 — Memory Exhaustion via Uncapped PDU Buffer Allocation (Critical DoS)

**File:** `DICOM/Network/DicomService.cs`, `ListenAndProcessPDUAsync()` (~line 648–656)

```csharp
var length = BitConverter.ToInt32(buffer, 2);
length = Endian.Swap(length);
if (length < 0)
{
    throw new DicomDataException("Invalid PDU length: " + length.ToString());
}

_readLength = length;
Array.Resize(ref buffer, length + 6);   // ← unbounded allocation
```

The 32-bit `length` field is taken directly from the network. The only guard is a
negative-value check. A `length` value of, for example, `0x1FFFFFFF` (~512 MB) will
cause the process to immediately allocate a 512 MB buffer for *every* simultaneous
inbound connection. An attacker on a LAN can exhaust physical memory on the server
in seconds by opening a small number of connections and sending PDU headers with
maximum length fields, without ever sending the bodies.

An additional integer-overflow hazard exists: if `length = Int32.MaxValue - 5`
(0x7FFFFFFA), then `length + 6` overflows to a negative `int`, and `Array.Resize`
throws `ArgumentOutOfRangeException`, crashing the listener loop.

**Suggestion:** Enforce a hard maximum on accepted PDU length before allocating. The
DICOM standard recommends a default maximum of 16384 bytes and allows negotiation up
to `MaximumPDULength`. Reject (and log) any PDU header that claims a length exceeding
the negotiated (or a hard-coded safe) maximum, for example 1 MB or the value in
`DicomServiceOptions.MaxDataBuffer`.

---

### FINDING-02 — Unsigned Integer Underflow Causes Infinite Loop in Association PDU Parsing (Critical DoS)

**File:** `DICOM/Network/PDU.cs`, `AAssociateRQ.Read()` (~line 616–624) and
`AAssociateAC.Read()` (~line 933–944)

```csharp
uint l = raw.Length - 6;
// ...
while (l > 0)
{
    byte type = raw.ReadByte("Item-Type");
    raw.SkipBytes("Reserved", 1);
    ushort il = raw.ReadUInt16("Item-Length");
    // ...
    l -= 4 + (uint)il;    // ← unsigned subtraction; wraps if il is too large
```

`l` is an unsigned 32-bit value. The attacker controls `il` through the `Item-Length`
field in the PDU. If the crafted `il` is larger than remaining `l - 4`, the subtraction
wraps around to a very large positive value (`uint` does not throw on underflow). The
`while (l > 0)` condition then remains true for a very long time, causing the receive
loop to spin consuming 100% CPU on one thread, blocking processing of all PDUs from
that connection and exhausting the thread pool with additional crafted connections.

**Suggestion:** Before each iteration subtract, check that `l >= 4 + il`. If not, the
PDU is malformed; reject the association.

---

### FINDING-03 — No Connection Limit Allows Connection-Flood DoS (High)

**File:** `DICOM/Network/DicomServer.cs`

The `clients` list in `DicomServer<T>` has no upper bound. Every accepted TCP
connection adds a new `DicomService` instance, each with its own listener task,
multiple queues, and stream buffers. An attacker can open thousands of TCP connections
to the DICOM port without sending any data. The `OnTimerTickAsync` cleanup only
removes connections after 10 minutes of inactivity. Until then, each idle connection
occupies memory and a Task Scheduler thread. This exhausts available memory and thread
pool capacity, causing legitimate connections to be refused or delayed.

**Suggestion:** Add a configurable `MaxClients` property to `DicomServiceOptions` (or
directly to `DicomServer`). When a new connection would exceed the limit, close the
TCP connection immediately after accepting it.

---

### FINDING-04 — `MaximumPDULength` Accepted from Network Without Upper Bound (High)

**File:** `DICOM/Network/PDU.cs`, `AAssociateRQ.Read()` (~line 704)

```csharp
_assoc.MaximumPDULength = raw.ReadUInt32("Max PDU Length");
```

The negotiated Maximum PDU Length is read directly from the network and stored without
validation. This value is subsequently used as the allocation size for PDU write
buffers in `PDataTFStream`. If a malicious SCU or SCP negotiates a
`MaximumPDULength` of `0xFFFFFFFF` (4 GB), any subsequent call that uses this value
for buffer allocation will trigger an `OutOfMemoryException`.

**Suggestion:** Clamp `MaximumPDULength` to a reasonable range (e.g., 4096 –
16,777,216 bytes) immediately after reading it, before it is stored in the association
object.

---

### FINDING-05 — Attacker-Controlled `MaxAsyncOpsPerformed` Permits Thread-Pool Exhaustion (High)

**File:** `DICOM/Network/PDU.cs` (~line 716–717), `DICOM/Network/DicomService.cs`,
`PerformDimse()` (~line 1268)

```csharp
// PDU.cs – read from wire
_assoc.MaxAsyncOpsPerformed = raw.ReadUInt16("Asynchronous Operations Performed");

// DicomService.cs – used as queue limit
if (Association.MaxAsyncOpsPerformed > 0 && totalOutstanding >= Association.MaxAsyncOpsPerformed)
{
    SendFailureResponse(dreq);
}
else
{
    _receivedQueue.Add(dreq);
}
PerformNextRequest();   // each entry spawns a Task.Run()
```

An attacker can set `MaxAsyncOpsPerformed` to 65 535 in the A-ASSOCIATE-RQ PDU.
`PerformDimse` then allows up to 65 535 simultaneously queued request-processing
`Task.Run()` tasks per connection. Multiplied over several connections, this
exhausts the .NET thread pool and starves all other work in the process.

**Suggestion:** Ignore the remote's `MaxAsyncOpsPerformed` for the purpose of
controlling the local processing concurrency, or cap its effective value at the
locally configured `DicomServiceOptions.MaxDimseConcurrency`.

---

### FINDING-06 — TLS 1.0 / 1.1 Permitted; TLS 1.3 Not Available (Medium)

**File:** `DICOM/Network/DesktopNetworkStream.cs`

- **Server side (non-NETSTANDARD):** `SslProtocols.Tls11 | SslProtocols.Tls12` — TLS
  1.1 is RFC 8996-deprecated and has known weaknesses (POODLE variants, BEAST).
- **Server side (NETSTANDARD):** `SslProtocols.Tls` — TLS *1.0 only*. TLS 1.0 has
  critical vulnerabilities and has been prohibited in FIPS 140-3 environments.
- **Client side (non-NETSTANDARD):** Same as server: `Tls11 | Tls12`.

In both cases, `SslProtocols.None` (which lets the OS negotiate the best available
version, including TLS 1.3) is not used, and TLS 1.0/1.1 downgrade attacks remain
possible for any peer that supports them.

**Suggestion:** Replace explicit protocol version constants with `SslProtocols.None`
on .NET Framework 4.7.2+ and .NET Standard 2.1+, which delegates version selection to
the OS/runtime and enables TLS 1.3. For older targets, use `SslProtocols.Tls12` as
the minimum and remove `SslProtocols.Tls11`.

---

### FINDING-07 — Certificate Validation Falls Back to Unvalidated Local Store Lookup (Medium)

**File:** `DICOM/Network/DesktopNetworkStream.cs`, `CertIsStoredLocally()` (~line
237–263), `VerifyCertificate()` (~line 212–235), `DummyCertificatValidationCallback()`
(~line 160–206)

When an SSL/TLS peer presents a certificate that fails the normal chain validation
(expired, untrusted CA, wrong hostname, revoked), both the client-side and server-side
validation callbacks fall back to searching the local machine certificate store
(`StoreName.My` and `"WebHosting"`) by serial number. If a certificate with a matching
serial number is found and the hash matches, the connection is accepted:

```csharp
// VerifyCertificate (client side)
if (CertIsStoredLocally(certificate)) return true;

// CertIsStoredLocally
if (certs != null && certs.Count == 1 && certs[0].GetCertHashString() == certificate.GetCertHashString())
{
    //todo: check cert validity?
    return true;
}
```

Problems:
1. **Expiry is not checked** (see the `TODO` comment). An expired certificate stored
   locally is permanently accepted.
2. **Trust model is inconsistent**: a certificate that fails hostname validation but
   is in the local store is still accepted. This can enable MITM attacks if an
   attacker's certificate is somehow in the store.
3. The `DummyCertificatValidationCallback` (server side) also strips the
   `RemoteCertificateNotAvailable` policy error and treats connections with no client
   certificate as valid, even when mutual authentication was requested.

**Suggestion:** Remove the `CertIsStoredLocally` fallback, or at minimum check
certificate expiry (`ValidTo`) and enforce the expected hostname (DNS name). If
self-signed or private CA certificates must be trusted, implement explicit
trust-anchor pinning rather than relying on the local machine store.

---

### FINDING-08 — `IgnoreSslPolicyErrors` Configuration Option Is a Dead Setting (Medium)

**File:** `DICOM/Network/DicomServiceOptions.cs` (property definition), 
`DICOM/Network/DesktopNetworkStream.cs` (constructor signature)

`DicomServiceOptions.IgnoreSslPolicyErrors` is documented as controlling whether SSL
certificate errors are ignored. It is passed all the way into
`DesktopNetworkStream`'s constructor, but the constructor parameter is never read
inside the class. The `VerifyCertificate` callback is a static method that captures
no context and does not reference this flag. As a result:

- Setting `IgnoreSslPolicyErrors = true` has no effect; certificate validation
  proceeds normally.
- Setting `IgnoreSslPolicyErrors = false` (the default) also has no effect relative
  to what callers expect.

If developers have relied on this option to "disable certificate validation for
testing", they may have believed their test certificate was being correctly validated
when it was actually being accepted by the `CertIsStoredLocally` fallback, or they
may have been confused by intermittent failures. More critically, if
`IgnoreSslPolicyErrors` were ever correctly wired up to skip all validation, it would
become a significant attack vector in production deployments that forget to turn it
off.

**Suggestion:** Either implement the option correctly (capture `ignoreSslPolicyErrors`
in a closure and return `true` from the callback when it is set), or remove both the
option and the constructor parameter and document that certificate validation is
always performed. The safest fix is the latter.

---

### FINDING-09 — User Identity Negotiation Silently Discarded — No SCU Authentication Hook (Medium)

**File:** `DICOM/Network/PDU.cs`, `AAssociateRQ.Read()` (~lines 746–763)

```csharp
else if (ut == 0x58)//User Identity Negotiation
{
    // ... all parsing code is commented out ...
    raw.SkipBytes("Unhandled User Item", ul);
}
```

DICOM User Identity Negotiation (PS 3.7, Annex D) allows an SCU to present a
username/password, Kerberos ticket, or SAML assertion during association setup so the
SCP can authenticate and authorize the caller. The parsing is entirely commented out
and the data is silently skipped. Because there is no parsed result and no callback
hook, SCP implementations built on fo-dicom cannot enforce user authentication even
if they want to.

**Suggestion:** Implement the commented-out parsing to populate a
`DicomUserIdentityNegotiation` property on `DicomAssociation`. Expose a
corresponding callback/virtual method in `IDicomServiceProvider.OnReceiveAssociationRequest`
so SCP developers can inspect the identity and reject the association if authentication
fails.

---

### FINDING-10 — Association Request Processing Continues After PDU Parse Failure (Medium)

**File:** `DICOM/Network/DicomService.cs`, `ListenAndProcessPDUAsync()` (~lines
691–727)

```csharp
var pdu = new AAssociateRQ(Association);
try
{
    pdu.Read(raw);
}
catch (Exception ex)
{
    Logger.Error("Error reading association request: " + ex.Message);  // note: "assocaition" in original
    Logger.Debug("...");
}
// ← execution falls through unconditionally
LogID = Association.CallingAE + " (" + Association.AssociationId.ToString() + ")";
// ...
(this as IDicomServiceProvider)?.OnReceiveAssociationRequest(Association);
```

If `pdu.Read(raw)` throws (e.g., because of a malformed PDU), the exception is caught
and logged, but `OnReceiveAssociationRequest` is still called with a *partially
populated* `Association` object. Fields like `CalledAE`, `CallingAE`, and the
presentation context list may be `null` or incomplete. An SCP implementation that
makes an accept/reject decision based on these fields will operate on corrupt data,
potentially accepting a connection it should have rejected, or throwing a
`NullReferenceException` that crashes the service handler.

**Suggestion:** After catching the parse exception, send an `A-ASSOCIATE-RJ` response
and close the connection instead of continuing.

---

### FINDING-11 — CallingAE Written to Log Without Sanitization (Log Injection) (Low–Medium)

**File:** `DICOM/Network/DicomService.cs` (~line 700)

```csharp
LogID = Association.CallingAE + " (" + Association.AssociationId.ToString() + ")";
```

`CallingAE` is a 16-byte string read directly from a network PDU and placed in `LogID`,
which is subsequently included verbatim in every log entry for the connection lifetime.
DICOM AE Titles are allowed to contain any printable ASCII character. A malicious peer
can inject newlines, ANSI escape sequences, or log-structured-data tokens into the
string, making log entries appear to be from a different AE, hide evidence of other
events, or confuse log-analysis tooling.

The same issue applies to `LogID` containing `Association.CalledAE`.

**Suggestion:** Sanitize `CallingAE` and `CalledAE` before using them in log strings.
At minimum, strip or replace control characters (bytes 0–31 and 127). DICOM PS 3.7
restricts AE Titles to uppercase letters, digits, spaces, and underscores; applying
that whitelist would also validate conformance.

---

### FINDING-12 — Race Condition in `DicomServer.Create` Port-Uniqueness Check (Low)

**File:** `DICOM/Network/DicomServer.cs`, `DicomServer.Create()` (~lines 411–422)

```csharp
if (Servers.Any(server => server.Port == port))        // check (not under lock)
{
    throw new DicomNetworkException("...");
}
lock (locker)
{
    return new DicomServer<T>(port, ...);               // act
}
```

The check that no server already exists on `port` is performed *outside* the lock.
Two concurrent calls with the same port can both pass the check before either acquires
the lock, resulting in two `DicomServer` instances both calling
`new TcpListener(IPAddress.Any, port)`. The second `Start()` call will throw
`SocketException: Only one usage of each socket address is normally permitted`, but by
that point one server is already running and both are registered.

**Suggestion:** Move the `Any()` check inside the `lock (locker)` block.

---

### FINDING-13 — Server Listens on All Interfaces with No Opt-In Restriction (Low)

**File:** `DICOM/Network/DesktopNetworkListener.cs` (~line 49)

```csharp
this.listener = new TcpListener(IPAddress.Any, port);
```

The TCP listener unconditionally binds to `0.0.0.0` (all IPv4 interfaces). There is
no option to restrict the server to a loopback or specific LAN interface. In
environments where the DICOM server is co-hosted with other services (e.g., a
web server on the same host), this exposes the DICOM port on every network interface,
including public-facing ones.

**Suggestion:** Add an optional `listenAddress` parameter to `DicomServer.Create()`
and `DesktopNetworkListener`, defaulting to `IPAddress.Any` for backward
compatibility, so operators can bind to a specific interface.

---

### FINDING-14 — XML Dictionary Loading Is Susceptible to XXE on .NET 3.5 (Low)

**File:** `DICOM/DicomDictionaryReader.cs` (~lines 41–48)

```csharp
#if NET35
    XDocument xdoc;
    using (var reader = new StreamReader(_stream))
    {
        xdoc = XDocument.Load(reader);   // ← DTD/entity processing may be enabled
    }
```

On .NET 3.5 (the `NET35` build target), `XDocument.Load` uses an `XmlReader` with
the default settings for that runtime, which *does* allow DTD processing and external
entity expansion. If an attacker can supply or modify a DICOM dictionary file, an
XXE payload in that file can read arbitrary files readable by the process, or make
network requests to internal hosts (Server-Side Request Forgery).

The non-NET35 path (`XDocument.Load(_stream)`) is safe on .NET 4.0+ because DTD
processing is `Prohibit` by default.

**Suggestion:** For the `NET35` path, construct an explicit `XmlReaderSettings` with
`DtdProcessing = DtdProcessing.Prohibit` and pass it to `XmlReader.Create`, then use
`XDocument.Load(xmlReader)`.

---

### FINDING-15 — No Maximum Connection Duration; Slow-Read / Slow-Write Keeps Resources Locked (Low)

**File:** `DICOM/Network/DicomServer.cs`, `OnTimerTickAsync()` (~line 354)

```csharp
else if (elapsed.TotalMinutes > 10) //close connections with no recent activity
{
    // disconnect
}
```

The inactivity timeout only fires when a connection sends *no* data for 10 minutes.
A "slow-read" or "slowloris"-style attacker can keep a connection alive indefinitely
by dribbling one byte every 9 minutes. Since each connection holds a thread pool
task, memory buffers, and a file descriptor, a single attacker can maintain an
unlimited number of arbitrarily long-lived connections at minimal bandwidth cost.

**Suggestion:** Add a configurable maximum association lifetime (e.g., 30 minutes
total wall-clock time regardless of activity) and a per-PDU receive timeout (e.g., a
PDU header must be completed within N seconds of the first byte arriving).

---

### FINDING-16 — `MaximumPDULength` Negotiation Uses Unauthenticated Remote Value on SCP (Informational)

**File:** `DICOM/Network/DicomService.cs`, `SendNextPDUAsync` and `DoSendMessage()`

After negotiation, `Association.MaximumPDULength` reflects the value the remote SCU
requested. The local SCP uses this value to size the `PDataTFStream` write buffer. If
the SCU requests a very small value (e.g., 100 bytes) it will fragment data into
many tiny PDUs, increasing overhead. This is a protocol-conformance issue rather than
a vulnerability, but in combination with FINDING-04 (no upper-bound check) it
represents a two-sided attack surface: too large OR too small.

---

## Summary Table

| ID | Severity | Component | Impact |
|----|----------|-----------|--------|
| 01 | Critical | `DicomService` PDU receive loop | OOM crash / process kill |
| 02 | Critical | `PDU.cs` AAssociateRQ/AC parser | CPU busy-loop / DoS |
| 03 | High | `DicomServer` connection management | Thread/memory exhaustion |
| 04 | High | `PDU.cs` MaximumPDULength | OOM crash |
| 05 | High | `DicomService` DIMSE dispatch | Thread-pool exhaustion |
| 06 | Medium | `DesktopNetworkStream` TLS config | Downgrade to deprecated TLS |
| 07 | Medium | `DesktopNetworkStream` cert validation | MITM; expired cert acceptance |
| 08 | Medium | `DicomServiceOptions` / `DesktopNetworkStream` | Silent misconfiguration |
| 09 | Medium | `PDU.cs` User Identity Negotiation | No SCU authentication possible |
| 10 | Medium | `DicomService` association setup | Corrupt association → wrong accept/reject |
| 11 | Low–Med | `DicomService` logging | Log injection |
| 12 | Low | `DicomServer.Create` | Duplicate server confusion |
| 13 | Low | `DesktopNetworkListener` | Unintended interface exposure |
| 14 | Low | `DicomDictionaryReader` | XXE on .NET 3.5 builds |
| 15 | Low | `DicomServer` cleanup timer | Resource exhaustion via slow connections |
| 16 | Info | `DicomService` PDU sizing | Protocol overhead |
