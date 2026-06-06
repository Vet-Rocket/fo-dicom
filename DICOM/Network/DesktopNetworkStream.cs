// Copyright (c) 2012-2017 fo-dicom contributors.
// Licensed under the Microsoft Public License (MS-PL).

namespace Dicom.Network
{
    using System;
    using System.IO;
    using System.Net;
    using System.Net.Security;
    using System.Net.Sockets;
    using System.Security.Authentication;
    using System.Security.Cryptography.X509Certificates;

    /// <summary>
    /// .NET implementation of <see cref="INetworkStream"/>.
    /// </summary>
    public sealed class DesktopNetworkStream : INetworkStream
    {
        #region FIELDS

        private bool disposed = false;

        private readonly TcpClient tcpClient;

        private readonly Stream networkStream;

        #endregion

        #region CONSTRUCTORS

        /// <summary>
        /// Initializes a client instance of <see cref="DesktopNetworkStream"/>.
        /// </summary>
        /// <param name="host">Network host.</param>
        /// <param name="port">Network port.</param>
        /// <param name="useTls">Use TLS layer?</param>
        /// <param name="noDelay">No delay?</param>
        /// <param name="ignoreSslPolicyErrors">Ignore SSL policy errors?</param>
        // ---------------------------------------------------------------------------------------
        // [REVIEW #3] DEAD PARAMETER: 'ignoreSslPolicyErrors'
        //   This parameter is accepted but never read anywhere in this constructor. The actual
        //   validation decision is made by the static VerifyCertificate callback below, which has
        //   no access to this instance-level flag. Consequences:
        //     - A caller passing ignoreSslPolicyErrors:true expecting lenient validation gets
        //       STRICT validation anyway (the flag is silently ignored).
        //     - Equally, a caller passing false cannot assume the flag is what enforces strictness.
        //   Security note: it is GOOD that this is not wired to a blanket "return true" (that would
        //   disable all server-cert validation and open the client to MITM). But a silently-ignored
        //   security-relevant flag is a footgun. Recommended resolution: either
        //     (a) DELETE the parameter and its call sites, or
        //     (b) WIRE IT IN deliberately. That requires making VerifyCertificate a non-static
        //         instance method (or capturing the flag in a lambda) so it can be consulted, e.g.
        //         "if (this.ignoreSslPolicyErrors) return true;" -- but only do this for explicit,
        //         opt-in dev/test scenarios, never as a default, and ideally log loudly when bypassed.
        // ---------------------------------------------------------------------------------------
        internal DesktopNetworkStream(string host, int port, bool useTls, bool noDelay, bool ignoreSslPolicyErrors, string certificateName)
        {
            this.RemoteHost = host;
            this.RemotePort = port;

#if NETSTANDARD
            this.tcpClient = new TcpClient { NoDelay = noDelay };
            this.tcpClient.ConnectAsync(host, port).Wait();
#else
            this.tcpClient = new TcpClient(host, port) { NoDelay = noDelay };
#endif

            Stream stream = this.tcpClient.GetStream();
            if (useTls)
            {
                X509CertificateCollection certs = null;
                if (!String.IsNullOrEmpty(certificateName))
                {
                    var cert = DesktopNetworkManager.GetX509Certificate(certificateName);
                    if (cert != null) certs = new X509CertificateCollection(new X509Certificate[] { cert });
                }

                // [REVIEW #3] VerifyCertificate is static, so it cannot see 'ignoreSslPolicyErrors'
                // (see the parameter note above). If you decide to honor that flag, this callback
                // must become an instance method or a closure that captures it.
                var ssl = new SslStream(
                    stream,
                    false,
                    new RemoteCertificateValidationCallback(VerifyCertificate), null, EncryptionPolicy.RequireEncryption);
#if !DEBUG
                ssl.ReadTimeout = 5000;
                ssl.WriteTimeout = 5000;
#endif

#if NETSTANDARD
                ssl.AuthenticateAsClientAsync(host).Wait();
#else
                //ssl.AuthenticateAsClientAsync(host, certs, SslProtocols.Tls11 | SslProtocols.Tls12, false).Wait(5000);
                try
                {
                    //don't specify tls version per microsoft
                    //https://learn.microsoft.com/en-us/dotnet/framework/network-programming/tls?tabs=47-plus%2Chttpclient-sslstream
                    // [OK] Correct: omitting SslProtocols lets Schannel negotiate the best version the
                    // OS supports (TLS 1.2 on Win10/Server 2019; TLS 1.3 on Win11/Server 2022). The
                    // third arg (checkCertificateRevocation:false) means the SERVER cert's revocation
                    // (CRL/OCSP) is NOT checked. Default trust/name/expiry validation still happens
                    // and is enforced by VerifyCertificate below. Set this to true only if you want
                    // revocation checking AND can tolerate the added network dependency/latency.
                    ssl.AuthenticateAsClient(host, certs, false);
                }
                catch (Exception x)
                {
                    // ===================================================================================
                    // [FIX #4] Preserve the original exception as InnerException.
                    //   Previously this threw new DicomNetworkException("..." + x.Message), which
                    //   flattened the failure to a string and DISCARDED the inner Win32/SSPI exception
                    //   and its stack trace. TLS handshake failures carry their diagnostic detail in
                    //   InnerException -- e.g. "The client and server cannot communicate, because they
                    //   do not possess a common algorithm" or "The specified data could not be
                    //   decrypted". Losing it makes failures (especially the TLS 1.3 ones you'll see
                    //   after moving to Server 2022) much harder to diagnose. This now mirrors the
                    //   server-side catch, which already passes 'x' as the inner exception.
                    //   (The old, unused "string err = x.Message;" local was removed -- it was dead.)
                    // ===================================================================================
                    throw new DicomNetworkException("Could not authenticate SSL connection as client: " + x.Message, x);
                }
#endif
                stream = ssl;

                // [REVIEW - SEMANTIC] 'Authenticated' is set from IsMutuallyAuthenticated, which is
                // true ONLY when BOTH peers presented and validated certificates. A normal client
                // connection that validates the server but presents no client cert of its own
                // (certs == null, i.e. no certificateName supplied) will report Authenticated == false
                // even though the channel is encrypted and the server cert was verified. Make sure no
                // downstream code treats Authenticated == false as a connection failure -- it would
                // reject perfectly valid server-authenticated-only sessions.
                this.Authenticated = ssl.IsMutuallyAuthenticated;
                this.Encrypted = ssl.IsEncrypted; ;
                stream.ReadTimeout = -1;
                stream.WriteTimeout = -1;
            }
            //possibly reset
            stream.ReadTimeout = -1;
            stream.WriteTimeout = -1;
            this.LocalHost = ((IPEndPoint)tcpClient.Client.LocalEndPoint).Address.ToString();
            this.LocalPort = ((IPEndPoint)tcpClient.Client.LocalEndPoint).Port;

            this.networkStream = stream;
        }

        /// <summary>
        /// Initializes a server instance of <see cref="DesktopNetworkStream"/>.
        /// </summary>
        /// <param name="tcpClient">TCP client.</param>
        /// <param name="certificate">Certificate for authenticated connection.</param>
        /// <remarks>Ownership of <paramref name="tcpClient"/> remains with the caller, including responsibility for
        /// disposal. Therefore, a handle to <paramref name="tcpClient"/> is <em>not</em> stored when <see cref="DesktopNetworkStream"/>
        /// is initialized with this server-side constructor.</remarks>
        internal DesktopNetworkStream(TcpClient tcpClient, X509Certificate certificate)
        {
            this.LocalHost = ((IPEndPoint)tcpClient.Client.LocalEndPoint).Address.ToString();
            this.LocalPort = ((IPEndPoint)tcpClient.Client.LocalEndPoint).Port;
            this.RemoteHost = ((IPEndPoint)tcpClient.Client.RemoteEndPoint).Address.ToString();
            this.RemotePort = ((IPEndPoint)tcpClient.Client.RemoteEndPoint).Port;

            Stream stream = tcpClient.GetStream();
            if (certificate != null)
            {
                var certSelection = new LocalCertificateSelectionCallback((object sender, string targetHost,
                    X509CertificateCollection localCertificates, X509Certificate remoteCertificate, string[] acceptableIssuers) =>
                {
                    return certificate;
                });

                var ssl = new SslStream(stream, false, new RemoteCertificateValidationCallback(ClientCertificatValidationCallback),
                    certSelection, EncryptionPolicy.RequireEncryption);
#if !DEBUG
                ssl.ReadTimeout = 5000;
                ssl.WriteTimeout = 5000;
#endif
#if NETSTANDARD
                ssl.AuthenticateAsServerAsync(certificate, false, SslProtocols.Tls, false).Wait();
#else
                //clientCertificateRequired is only a request, not an actual requirement
                //https://learn.microsoft.com/en-us/dotnet/api/system.net.security.sslstream.authenticateasserver?view=netframework-4.7.2
                try
                {
                    //ssl.AuthenticateAsServer(certificate, true, SslProtocols.Tls11 | SslProtocols.Tls12, false);
                    //don't specify tls version per microsoft
                    //https://learn.microsoft.com/en-us/dotnet/framework/network-programming/tls?tabs=47-plus%2Chttpclient-sslstream
                    // -------------------------------------------------------------------------------
                    // [REVIEW #1] TLS 1.3 BEHAVIOR CHANGE -- LATENT TODAY, ACTIVE ON SERVER 2022.
                    //   Omitting SslProtocols (correct) means this negotiates TLS 1.2 on your current
                    //   Server 2019 fleet but TLS 1.3 once a server is on Server 2022 / Windows 11.
                    //   Under TLS 1.2 the client certificate is exchanged DURING the handshake, so by
                    //   the time this call returns, IsMutuallyAuthenticated (read below) is accurate.
                    //   Under TLS 1.3, client authentication moves to AFTER the main handshake. The
                    //   documented SslStream behavior in that mode is that authentication can report
                    //   success / report state that does not reflect the final client-cert outcome
                    //   until the first Read on the stream. So on Server 2022, BOTH of these become
                    //   suspect: (a) the IsMutuallyAuthenticated value read immediately below, and
                    //   (b) the anonymous-client detection in ClientCertificatValidationCallback.
                    //   NOTE: this is extrapolated from a .NET 6 client-side report to this .NET
                    //   Framework server case -- VERIFY empirically against a TLS 1.3 listener before
                    //   rolling out to Server 2022; do not assume "works on 2019" => "works on 2022".
                    //
                    //   Also (already noted in the comment above): clientCertificateRequired:true only
                    //   REQUESTS a client cert; a client that sends none is still accepted. Real
                    //   enforcement lives in ClientCertificatValidationCallback, not in this flag.
                    // -------------------------------------------------------------------------------
                    ssl.AuthenticateAsServer(certificate, true, false);

                }
                catch (Exception x)
                {
                    try
                    {
                        ssl.Dispose();
                    }
                    catch { }
                    // [OK] Server side already preserves the inner exception ('x'). This is the
                    // pattern the client catch (FIX #4) was brought in line with.
                    throw new DicomNetworkException("Could not authenticate SSL connection as server", x);
                }
#endif
                stream = ssl;

                // [REVIEW #1 / SEMANTIC] See the TLS 1.3 note above: on Server 2022 the value read
                // here may not yet reflect the post-handshake client-cert outcome. Also, as on the
                // client side, IsMutuallyAuthenticated is false for an anonymous (no client cert)
                // connection even though it is encrypted and valid -- expected, given your policy
                // intentionally accepts anonymous clients.
                this.Authenticated = ssl.IsMutuallyAuthenticated;
                this.Encrypted = ssl.IsEncrypted;
                stream.ReadTimeout = -1;
                stream.WriteTimeout = -1;
                string msg = "Secure connection established; Encrypted: " + ssl.IsEncrypted.ToString() + ", Mutually Authenticated: " + ssl.IsMutuallyAuthenticated.ToString();
                msg += ", SslProtocol: " + ssl.SslProtocol.ToString();
                Log.LogManager.GetLogger("DicomServer").Info(msg);
            }
            this.networkStream = stream;
        }

        // SERVER-SIDE validation of the REMOTE (client) certificate. Invoked because the server
        // requested a client cert (clientCertificateRequired:true). Return value decides acceptance.
        private static bool ClientCertificatValidationCallback(object sender, X509Certificate certificate, X509Chain chain, SslPolicyErrors sslPolicyErrors)
        {
            bool isOkay = false;
            string logMsg = "Connection requested ";
            if (certificate != null)
            {
                logMsg += "with certficate '" + certificate.Subject + "'";
                if (sslPolicyErrors == SslPolicyErrors.None)
                {
                    isOkay = true;
                }
                else
                {
                    //check for local certs
                    if (CertIsStoredLocally(certificate))
                    {
                        isOkay = true;
                        logMsg += ", matches local";
                    }
                    else
                    {
                        logMsg += ", but has errors: " + sslPolicyErrors.ToString();
                    }
                }
                logMsg += "\nCertificate:\n" + certificate.ToString().Replace("\r", "").Replace("]\n", "]").Replace("\n\n", "\n");
            }
            else
            {
                // [REVIEW #1] ANONYMOUS-CLIENT PATH -- sensitive to the TLS 1.3 timing change above.
                //   Here we clear RemoteCertificateNotAvailable and then accept if nothing else is
                //   wrong, i.e. we permit cert-less ("anonymous") clients. Under TLS 1.2 a missing
                //   client cert is known by the time this callback runs. Under TLS 1.3, because client
                //   auth is post-handshake, WHEN/WHETHER this callback is invoked for the cert-less
                //   case (and what flags it carries) can differ. Re-test the anonymous path
                //   specifically on Server 2022 to confirm cert-less clients are still accepted as
                //   intended and that a genuinely-required cert still surfaces as expected.
                logMsg += "with anonymous TLS encryption";
                sslPolicyErrors &= ~SslPolicyErrors.RemoteCertificateNotAvailable;
                if (sslPolicyErrors == SslPolicyErrors.None)
                {
                    isOkay = true;
                }
                else
                {
                    logMsg += ", but has errors: " + sslPolicyErrors.ToString();
                }
            }
            if (isOkay)
            {
                Log.LogManager.GetLogger("DicomServer").Info(logMsg);
                return true;
            }
            Log.LogManager.GetLogger("DicomServer").Warn(logMsg);
            return false;
        }
        //private static X509Certificate LocalCertificateValidationCallback(object sender, string targetHost, X509CertificateCollection localCertificates, X509Certificate remoteCertificate, string[] acceptableIssuers)
        //{
        //    if (localCertificates != null && localCertificates.Count > 0) return localCertificates[0];
        //    return null;
        //}

        // CLIENT-SIDE validation of the REMOTE (server) certificate.
        // [OK] This is the secure pattern: reject null, accept only when sslPolicyErrors == None,
        // otherwise fall through to an explicit local-store (pinning) check. It does NOT blanket
        // "return true", which is the single most common SslStream MITM hole. Good.
        static bool VerifyCertificate(object sender, X509Certificate certificate, X509Chain chain, SslPolicyErrors sslPolicyErrors)
        {
            if (certificate == null)
            {
                Log.LogManager.GetLogger("DicomClient").Warn("TLS connection with no certificate");
                return false;
            }
            if (sslPolicyErrors == SslPolicyErrors.None)
            {
                Log.LogManager.GetLogger("DicomClient").Info("TLS connection with certificate:" + certificate.Subject);
                return true;
            }
            try
            {
                //check for local certs
                if (CertIsStoredLocally(certificate)) return true;
            }
            catch (Exception ex)
            {
                Log.LogManager.GetLogger("DicomClient").Warn("TLS certificate:" + certificate.Subject + " could not be located: " + ex.Message);
            }
            Log.LogManager.GetLogger("DicomClient").Warn("TLS connection with certificate:" + certificate.Subject + " has errors " + sslPolicyErrors.ToString());
            return false;
        }

        // Explicit-trust ("pinning") check: treat a cert as trusted iff the exact same cert
        // (matched by serial number, then confirmed by thumbprint) exists in a local store.
        private static bool CertIsStoredLocally(X509Certificate certificate)
        {
            if (certificate != null)
            {
                X509Certificate2Collection certs = null;
                string certSerial = certificate.GetSerialNumberString();
                using (var store = new X509Store(StoreName.My, StoreLocation.LocalMachine))
                {
                    store.Open(OpenFlags.ReadOnly);
                    certs = store.Certificates.Find(X509FindType.FindBySerialNumber, certSerial, false);
                }
                if (certs == null || certs.Count == 0)
                {
                    using (var store = new X509Store("WebHosting", StoreLocation.LocalMachine))
                    {
                        store.Open(OpenFlags.ReadOnly);
                        certs = store.Certificates.Find(X509FindType.FindBySerialNumber, certSerial, false);
                    }
                }
                // -----------------------------------------------------------------------------------
                // [REVIEW #2] NO VALIDITY (EXPIRY) CHECK ON PINNED CERTS.
                //   This returns true based solely on identity (serial + thumbprint match) and does
                //   NOT inspect NotBefore/NotAfter. Effect: a pinned cert that has EXPIRED (or one you
                //   intended to retire but left in the store) is still accepted, bypassing the expiry
                //   enforcement that default validation would have applied. If your rotation process
                //   removes superseded certs from the store, the window is small; if old certs linger,
                //   they remain trusted past expiry. If that is not acceptable, gate the result on
                //   validity, e.g.:
                //       var match = certs[0];                       // already a X509Certificate2
                //       var now = DateTime.Now;
                //       if (now < match.NotBefore || now > match.NotAfter) return false;
                //   (Decide explicitly whether revocation also matters here; pinning usually implies
                //   you accept the cert regardless of CRL/OCSP, but expiry is a separate, cheap check.)
                //
                // [REVIEW #5] THUMBPRINT ALGORITHM (defense-in-depth).
                //   GetCertHashString() is the SHA-1 thumbprint. For matching against your OWN local
                //   store this is acceptable (it's an identity lookup, not a signature). For extra
                //   robustness you could compare a SHA-256 thumbprint or the public key (Subject
                //   PublicKeyInfo) instead, removing any theoretical SHA-1 collision concern. Low
                //   priority -- noting it for completeness.
                // -----------------------------------------------------------------------------------
                if (certs != null && certs.Count == 1 && certs[0].GetCertHashString() == certificate.GetCertHashString())
                {
                    //todo: check cert validity?  <-- see [REVIEW #2] above: add NotBefore/NotAfter check here if expiry must be enforced.
                    return true;
                }
            }
            return false;
        }

        /// <summary>
        /// Destructor.
        /// </summary>
        ~DesktopNetworkStream()
        {
            this.Dispose(false);
        }

        #endregion

        #region PROPERTIES

        /// <summary>
        /// Gets the remote host of the network stream.
        /// </summary>
        public string RemoteHost { get; }

        /// <summary>
        /// Gets the local host of the network stream.
        /// </summary>
        public string LocalHost { get; }

        /// <summary>
        /// Gets the remote port of the network stream.
        /// </summary>
        public int RemotePort { get; }

        /// <summary>
        /// Gets the local port of the network stream.
        /// </summary>
        public int LocalPort { get; }

        public bool Encrypted { get; }

        public bool Authenticated { get; }

        #endregion

        #region METHODS

        public Socket GetSocket()
        {
            if (this.tcpClient != null)
            {
                return this.tcpClient.Client;
            }
            return null;
        }

        public bool IsConnected
        {
            get
            {

                Socket sock = GetSocket();
                if (sock != null) return sock.Connected;
                return false;
            }
        }

        /// <summary>
        /// Get corresponding <see cref="Stream"/> object.
        /// </summary>
        /// <returns>Network stream as <see cref="Stream"/> object.</returns>
        public Stream AsStream()
        {
            return this.networkStream;
        }

        /// <summary>
        /// Performs application-defined tasks associated with freeing, releasing, or resetting unmanaged resources.
        /// </summary>
        public void Dispose()
        {
            this.Dispose(true);
            GC.SuppressFinalize(this);
        }

        /// <summary>
        /// Do the actual disposal.
        /// </summary>
        /// <param name="disposing">True if called from <see cref="Dispose"/>, false otherwise.</param>
        /// <remarks>The underlying stream is normally passed on to a <see cref="DicomService"/> implementation that
        /// is responsible for disposing the stream when appropriate. Therefore, the stream should not be disposed here.</remarks>
        private void Dispose(bool disposing)
        {
            if (this.disposed) return;

            if (this.tcpClient != null)
            {
#if NETSTANDARD
                this.tcpClient.Dispose();
#else
                this.tcpClient.Close();
#endif
            }

            this.disposed = true;
        }

        #endregion
    }
}
