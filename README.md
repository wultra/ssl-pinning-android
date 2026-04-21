# Dynamic SSL pinning for Android
<!-- begin remove -->
`WultraSSLPinning` is an Android library implementing dynamic SSL pinning, written in Kotlin.
<!-- end -->
<!-- begin TOC -->
- [Installation](#installation)
    - [Requirements](#requirements)
    - [Gradle](#gradle)
- [Usage](#usage)
    - [Configuration](#configuration)
    - [Predefined Fingerprints](#predefined-fingerprints)
- [Updating Fingerprints](#updating-fingerprints)
- [Fingerprint Validation](#fingerprint-validation)
   - [Global Validation Observers](#global-validation-observers)
- [Certificate Depth Pinning](#certificate-depth-pinning)
- [Domain Bypass Configuration](#domain-bypass-configuration)
- [Integration](#integration)
   - [PowerAuth Integration](#powerauth-integration)
   - [PowerAuth Integration from Java](#powerauth-integration-from-java)
   - [Integration with HttpsUrlConnection](#integration-with-httpsurlconnection)
   - [Integration with OkHttp](#integration-with-okhttp)
- [Switching Server Certificate](#switching-server-certificate)
- [FAQ](#faq)
- [License](#license)
- [Contact](#contact)
    - [Security Disclosure](#security-disclosure)
<!-- end -->

The SSL pinning (or [public key, or certificate pinning](https://en.wikipedia.org/wiki/Transport_Layer_Security#Certificate_pinning)) 
is a technique mitigating [Man-in-the-middle attacks](https://en.wikipedia.org/wiki/Man-in-the-middle_attack) against the secure HTTPS communication. 

The typical Android solution is to bundle the hash of the certificate, or the exact data of the certificate into the application. The connection is then validated via `X509TrustManager`.

The popular `OkHttp` library has a built-in `CertificatePinner` class that simplifies the integration.

In general, this works well, but it has, unfortunately, one major drawback, the certificate's expiration date. The certificate expiration forces you to update your application regularly before the certificate expires. Unfortunately, some percentage of users don't update their apps automatically. In effect, users on older versions, will not be able to contact the application servers.

A solution to this problem is the **dynamic SSL pinning**, where a list of certificate fingerprints is securely downloaded from the remote server.

The `WultraSSLPinning` library does precisely this:

- Manages the dynamic list of certificates, downloaded from the remote server.
- All entries in the list are signed with your private key and validated in the library using the public key (we're using the ECDSA-SHA-256 algorithm)
- Provides easy-to-use fingerprint validation on the TLS handshake.

Before you start using the library, you should also check our other related projects:

- [Mobile Utility Server](https://github.com/wultra/mobile-utility-server) - the server component that provides dynamic JSON data consumed by this library.
- [iOS version](https://github.com/wultra/ssl-pinning-ios) of the library

## Installation

### Requirements

- `minSdkVersion 23` (Android 6 Marshmallow)

### Gradle

To use **WultraSSLPinning** in your Android app add this dependency:

```gradle
implementation 'com.wultra.android.sslpinning:wultra-ssl-pinning:1.x.y'
```

Note that this documentation is using version `1.x.y` as an example. You can find the latest version on [github's release](https://github.com/wultra/ssl-pinning-android/releases#docucheck-keep-link) page. The Android Studio IDE can also find and offer updates for your application’s dependencies.

Also, make sure you have the `mavenCentral()` repository among the project repositories.

## Usage

- `CertStore` - the main class which provides all the library features
- `CertStoreConfiguration` - the configuration class for the `CertStore` class

The next chapters of this document will explain how to configure and use `CertStore` for SSL pinning purposes.

### Configuration

An example of `CertStore` configuration in Kotlin:

```kotlin
val publicKey: ByteArray = Base64.decode("BMne....kdh2ak=", Base64.NO_WRAP)
val configuration = CertStoreConfiguration.Builder(
                            serviceUrl = URL("https://..."), 
                            publicKey = publicKey)
                        .useChallenge(true)
                        .identifier(identifier)
                        .expectedCommonNames(expectedCommonNames)
                        .fallbackCertificates(fallbackCertificates)
                        .build()
val certStore = CertStore(configuration, appContext)
```

The configuration has the following properties:

- `serviceUrl` - parameter defining URL with a remote list of certificates (JSON).
- `publicKey` - a byte array containing the public key counterpart to the private key, used for fingerprint signing.
- `useChallenge` - parameter that defines whether the remote server requires a challenge request header:
  - use `true` in case you're connecting to [Mobile Utility Server](https://github.com/wultra/mobile-utility-server) or similar service.
  - use `false` in case the remote server provides static data, generated by [SSL Pinning Tool](https://github.com/wultra/ssl-pinning-tool).
- `expectedCommonNames` - an optional array of strings, defining which domains you expect in certificate validation.
- `identifier` - optional string identifier for scenarios, where multiple `CertStore` instances are used in the application.
- `fallbackCertificates` - optional hardcoded data for fallback fingerprints. See the next chapter of this document for details.
- `periodicUpdateIntervalMillis` - defines interval for default updates. The default value is 1 week.
- `expirationUpdateThreshold` - defines the time window before the next certificate will expire. In this time window `CertStore` will try to update the list of fingerprints more often than usual. The default value is 2 weeks before the next expiration.
- `executorService` - defines `java.util.concurrent.ExecutorService` for running updates. If not defined updates run on a dedicated thread (not pooled).
- `sslValidationStrategy` - defines the validation strategy for HTTPS connections initiated from the library itself. If not set, then the standard certificate chain validation provided by the operating system is used. Be aware that altering this option may put your application at risk. You should not ship your application to production with SSL validation turned off. See [FAQ](#download-fingerprints-from-test-server) for more details.

### Predefined Fingerprints

The `CertStoreConfiguration` may contain optional data with predefined certificate fingerprints. This technique can speed up the first application's startup when the database of fingerprints is empty. You still need to [update](#updating-fingerprints) your application, once the fallback fingerprints expire.

To configure the property, you need to provide an array of `GetFingerprintResponse.Entry` objects with fallback certificate fingerprints. The data should contain the same data as are usually received from the server, except that the `signature` property is not validated (but must be provided). The optional `depth` field specifies the certificate chain position (0 = leaf, the default).

> **Important:** Only fallback **certificates** (fingerprints) are supported in `fallbackCertificates`. The `DomainsConfig` object is intentionally **not** supported in fallback data — domain bypass rules take effect only when received from the server.

For example:

```kotlin
val fallbackEntry = GetFingerprintResponse.Entry(
                       name = "github.com",
                       fingerprint = fingerprintBytes,
                       expires = Date(1591185600000),
                       signature = ByteArray(0),
                       depth = 0)
val configuration = CertStoreConfiguration.Builder(
                            serviceUrl = URL("https://..."),
                            publicKey= publicKey)
                    .fallbackCertificates(arrayOf(fallbackEntry))
                    .build()
val certStore = CertStore(configuration, appContext)
```

## Updating Fingerprints

To update the list of fingerprints from the remote server, use the following code:

```kotlin
certStore.update(UpdateMode.DEFAULT, object: DefaultUpdateObserver() {
    override fun continueExecution() {
        // CertStore is likely up-to-date, you can resume execution of your code.
    }

    override fun handleFailedUpdate(type: UpdateType, result: UpdateResult) {
        // There was an error during the update. Present an error to the user.
    }

})
```

The method is asynchronous. `DefaultUpdateObserver` has two callbacks:

- `continueExecution()` tells you that the `CertStore` likely contains up-to-date data and your application should continue with the flow.
- `handleFailedUpdate(UpdateType, UpdateResult)` tells you that there was an error during the update execution you should handle.

Both callbacks are notified on the main thread.

`DefaultUpdateObserver` is the default implementation of `UpdateObserver`. In case you need more control over the flow, you can use the interface directly:

```kotlin
certStore.update(UpdateMode.DEFAULT, object: UpdateObserver() {
    override fun onUpdateStarted(type: UpdateType) {
        // CertStore update started, either in DIRECT, SILENT or NO_UPDATE mode 
    }

    override fun onUpdateFinished(type: UpdateType, result: UpdateResult) {
        // CertStore update of a given type finished asynchronously with some result.
    }

})
```

The method is asynchronous. `UpdateObserver` has two callbacks:

- `onUpdateStarted(UpdateType)` tells you what type of update has been started
- `onUpdateFinished(UpdateType, UpdateResult)` tells you the result and type of the update

Both callbacks are notified on the main thread.

There are three update types:

- `UpdateType.DIRECT` - The update is either **forced** or the library is missing essential data (fingerprints). The app is not advised to continue until the update is finished because there's a high risk of failing network requests due to server certificates being evaluated as untrusted.
- `UpdateType.SILENT` - The update is not critical but will be performed. The library has data but the data are going to expire soon. There's a low risk of failing network requests due to server certificates being evaluated as untrusted.
- `UpdateType.NO_UPDATE` - No update will be performed. The library has data and they are not going to expire soon. There's a low risk of failing network requests due to server certificates being evaluated as untrusted.

The update function works in two basic modes:

- **Forced mode**, this happens when the mode is forced (`UpdateMode.FORCED`).
- **Default mode**, this mode does internal evaluation of the stored data and configuration and tries to avoid unnecessary downloads when the data are ok.

<!-- begin box warning -->
Note: In any update type, there's still a risk of failing network requests due to server certificates being evaluated as untrusted. This is because the server certificate might be replaced at any time and the library might not be aware of it yet. To mitigate these cases it's recommended to implement a [global validation observer](#global-validation-observers).
<!-- end -->

Updates are performed on an `ExecutorService` defined in the configuration, if not defined, the update runs on a dedicated thread.

Note that your app is responsible for invoking the update method. The app typically has to call the update during the application's startup, before the first secure HTTPS request is initiated to a server that's supposed to be validated with the pinning.

## Fingerprint Validation

The `CertStore` provides several methods for certificate fingerprint validation. You can choose the one which suits best your scenario:

```kotlin
// [ 1 ]  If you already have the common name (e.g. domain) and certificate fingerprint

val commonName = "yourdomain.com"
val fingerprint: ByteArray = ...
val validationResult = certStore.validateFingerprint(commonName, fingerprint)

// [ 2 ]  If you already have the common name and the certificate data (in DER format)
val commonName = "yourdomain.com"
val certData: ByteArray = ...
val validationResult = certStore.validateCertificateData(commonName, certData)

// [ 3 ]  You want to validate java.security.cert.X509Certificate
val certificate: java.security.cert.X509Certificate = connection.getServerCertificates()[0]
val validationResult = certStore.validateCertificate(certificate)

// [ 4 ]  Validate a full TLS certificate chain. `depth` is determined automatically from entries stored in `certStore`.

val chain: Array<X509Certificate> = ...   // full TLS chain, chain[0] is the leaf
val validationResult = certStore.validateCertificateChain(chain)

// [ 5 ]  Validate a certificate at a specific depth (see "Certificate Depth Pinning")

val validationResult = certStore.validateFingerprint(commonName, fingerprint, depth = 1)
val validationResult = certStore.validateCertificateData(commonName, certData, depth = 1)
```

The `validateFingerprint` and `validateCertificateData` overloads accept an explicit `depth` and match only entries stored at that depth. `validateCertificateChain(chain)` does **not** accept a `depth` parameter — it automatically validates all pinned entries across every depth (see [Certificate Depth Pinning](#certificate-depth-pinning)).

Each `validate...` method returns the `ValidationResult` enum with the following options:

- `ValidationResult.TRUSTED` - the server certificate is trusted. You can continue with the connection. The right response in this situation is to continue with the ongoing communication.
- `ValidationResult.UNTRUSTED` - the server certificate is not trusted. You should cancel the ongoing connection. The untrusted result means that `CertStore` has some fingerprints stored in its database, but none matches the value you requested for validation. The right response to this situation is always to cancel the ongoing connection.
- `ValidationResult.EMPTY` - the fingerprint database is empty, or there's no fingerprint for the validated common name. The "empty" validation result typically means that the `CertStore` should update the list of certificates immediately. Before you do this, you should check whether the requested common name is what you're expecting. To simplify this step, you can set the list of expected common names in the `CertStoreConfiguration` and treat all others as untrusted.
    
For all situations, the right response in this situation is always to cancel the ongoing connection.


The full challenge handling in your app may look like this:

```kotlin
val url = new URL("https://mydomain.com/")
val urlConnection = url.openConnection() as javax.net.ssl.HttpsURLConnection
urlConnection.connect()

val serverCert = urlConnection.getServerCertificates()[0]
val validationResult = certStore.validateCertificate(serverCert)
if (validationResult != ValidationResult.TRUSTED) {
    throw javax.net.ssl.SSLException()
}
```

### Global Validation Observers

In order to be notified about all validation failures there is the `ValidationObserver` interface and methods on `CertStore` for adding/removing global validation observers.

The motivation for these global validation observers is that some validation failures (e.g. those happening in `SSLSocketFactory` instances created by `SSLSocketIntegration.createSSLPinningSocketFactory(CertStore)`) are out of reach of the app integrating the pinning library. These global validation observers are notified about all validation failures. The app can then react with force updating the fingerprints.

## Certificate Depth Pinning

By default the library pins the **leaf certificate** — the certificate the server presents directly. For stronger protection against a compromised leaf certificate you can instead pin an **intermediate CA** or the **root CA** in the certificate chain.

The `depth` value refers to the position of the certificate in the TLS chain as received in `X509TrustManager.checkServerTrusted(chain, authType)`, where `chain[0]` is the leaf. Note that the root CA may or may not be included in this provided chain:

| depth | certificate |
|-------|-------------|
| `0`   | Leaf (server) certificate — default |
| `1`   | First intermediate CA |
| `2`   | Second intermediate CA (if present) |
| `N`   | Root CA |

The [Mobile Utility Server](https://github.com/wultra/mobile-utility-server) stores the `depth` for each registered fingerprint and includes it in the response. When you call `validateCertificateChain(chain)`, the SDK automatically iterates over **all** pinned entries for the domain and validates each one against the certificate at its stored depth in the live TLS chain. The chain is trusted as soon as any entry matches.

```kotlin
// No depth parameter needed — the SDK resolves depth automatically for each stored entry
override fun checkServerTrusted(chain: Array<out X509Certificate>, authType: String) {
    val result = certStore.validateCertificateChain(chain)
    if (result != ValidationResult.TRUSTED) {
        throw CertificateException("Certificate chain is not trusted: $result")
    }
}
```

To pin an intermediate CA simply register its fingerprint at `depth: 1` in the Mobile Utility Server — no code change is needed in your app.

**Important notes:**

- Depth is **configured server-side** in the Mobile Utility Server and carried in the downloaded fingerprint list. There is no `depth` parameter on `validateCertificateChain(chain)`.
- Fingerprints stored at depth 0 are only matched against the leaf certificate; fingerprints stored at depth 1 are only matched against the first intermediate, and so on. A fingerprint stored at one depth is never compared against a certificate at a different depth.
- The leaf common name (chain[0]) is always used to look up stored fingerprints, regardless of depth.
- If a stored depth value exceeds the actual TLS chain length, that entry is silently skipped. Other entries for the same domain are still evaluated.
- Multiple fingerprints for the same domain at different depths are fully supported and validated together in a single `validateCertificateChain(chain)` call.

## Domain Bypass Configuration

The [Mobile Utility Server](https://github.com/wultra/mobile-utility-server) can mark specific domains as not requiring SSL pinning. When the server includes this configuration in its response the SDK respects it transparently — no code changes are needed in your app.

### How it works

The server response may include a `domainsConfig` object:

```json
{
  "fingerprints": [...],
  "domainsConfig": {
    "sslPinningRequiredForUnlisted": true,
    "domains": [
      { "name": "bypass.example.com", "sslPinningRequired": false },
      { "name": "api.example.com",    "sslPinningRequired": true  }
    ]
  }
}
```

The SDK applies the following rules on every call to `validate...`:

1. If the domain appears in `domains` with `sslPinningRequired: false` → returns `TRUSTED` immediately, no fingerprint check.
2. If the domain appears in `domains` with `sslPinningRequired: true` → normal fingerprint-based validation applies.
3. If the domain is **not** in the list:
  - `sslPinningRequiredForUnlisted: true` → normal fingerprint-based validation (default server behaviour).
  - `sslPinningRequiredForUnlisted: false` → returns `TRUSTED` immediately.

The `domainsConfig` is cached locally alongside the fingerprints and cleared whenever the server sends a response without it.

> **Important:** `domainsConfig` is supported **only** when received from the server. It is intentionally **not** supported in `fallbackCertificates` — there is no fallback mechanism for domain bypass rules.

### Migration notes

#### 1.5.x to 1.6.x

`UpdateResult.STORE_IS_EMPTY` has been removed. It was previously returned when the server responded with an empty `fingerprints` array. The update now returns `UpdateResult.OK` in that case, because an empty fingerprint list is a valid server response (e.g. when all certificates have been removed). If your code handles `STORE_IS_EMPTY` explicitly, remove that branch — no error handling is needed for this case.

The internal cache format was extended with an optional `depth` field for each stored certificate entry. When the field is absent (e.g. in caches written by version 1.5.x), it defaults to `0` (leaf certificate). Existing caches are fully compatible with 1.6.x — no cache reset, server update, or integrator action is required.

`validateCertificateChain(chain)` automatically validates **all** pinned entries for the domain, each at its stored depth. The result is `TRUSTED` as soon as any entry matches, `UNTRUSTED` if entries were found but none matched, and `EMPTY` if no applicable entries exist. All previously written `validateCertificateChain(chain)` call sites continue to compile and behave correctly.

The `depth` parameter is still available on `validateFingerprint(commonName, fingerprint, depth)` and `validateCertificateData(commonName, certificateData, depth)` for cases where you supply the fingerprint or certificate data yourself.

## Integration

### PowerAuth Integration

The **WultraSSLPinning** library contains classes for integration with the PowerAuth SDK. The most important one is the `PowerAuthSslPinningValidationStrategy` class, which implements `PA2ClientValidationStrategy` with SSL pinning. You can simply instantiate in with an existing `CertStore` and set it in `PA2ClientConfiguration`. Then the class will provide SSL pinning for all communication initiated within the PowerAuth SDK.

For example, this is how the configuration sequence may look like if you want to use both, `PowerAuthSDK` and `CertStore`:

```kotlin
val certStoreConfiguration = CertStoreConfiguration.Builder(
                            serviceUrl = URL("https://..."),
                            publicKey= publicKey)
                    .fallbackCertificates(fallbackCertificates)
                    .build()
                    
val powerAuthCertStore = CertStore.powerAuthCertStore(certStoreConfiguration, appContext)

val powerAuthConfiguration = PowerAuthConfiguration.Builder(
                appContext.packageName,
                BuildConfig.PA_SDK_CONFIG
            ).build()

val sslPinningValidationStrategy = PowerAuthSslPinningValidationStrategy(powerAuthCertStore)

val powerAuthClientConfiguration = PowerAuthClientConfiguration.Builder()
                .clientValidationStrategy(sslPinningValidationStrategy)
                .allowUnsecuredConnection(false)
                .build()
                
val powerAuth = PowerAuthSDK.Builder(powerAuthConfiguration)
                .clientConfiguration(powerAuthClientConfiguration)
                .build(appContext)
```

### PowerAuth Integration From Java

Some of Kotlin's PowerAuthSDK integration APIs are inconvenient in Java. A `CertStore` integrating PowerAuthSDK can be created with:

```java
CertStore store = PowerAuthCertStore.createInstance(configuration, context);
```

Or:

```java
CertStore store = PowerAuthCertStore.createInstance(configuration, context, "my-keychain-identifier");
```

Note that Kotlin's way of construction `CertStore.powerAuthCertStore` is not available in Java. Calling this in Java would be way too cumbersome, but will work:

```java
PowerAuthIntegrationKt.powerAuthCertStore(CertStore.Companion, configuration, context, null);`
```

### Integration With `HttpsUrlConnection`

For integration with HttpsUrlConnection use `SSLSocketFactory` provided by `SSLPinningIntegration.createSSLPinningSocketFactory(...)` methods.

The code will look like this:

```kotlin
val url = URL(...)
val connection = url.openConnection() as HttpsURLConnection

connection.sslSocketFactory = SSLPinningIntegration.createSSLPinningSocketFactory(store)

connection.connect()
```

### Integration With `OkHttp`

To integrate with OkHttp, use the following code:
 
```kotlin
val sslSocketFactory = SSLPinningIntegration.createSSLPinningSocketFactory(certStore);
val trustManager = SSLPinningX509TrustManager(certStore)

val okhttpClient = OkHttpClient.Builder()
                .sslSocketFactory(sslSocketFactory, trustManager)
                .build()
```

In the code above, use `SSLSocketFactory` provided by `SSLPinningIntegration.createSSLPinningSocketFactory(...)` and an instance of `SSLPinningX509TrustManager`.

## Switching Server Certificate

Certificate pinning is great for your app's security but at the same time, it requires care when deploying it to your customers. Be careful with the update parameters in `CertStoreConfiguration` serving for the default updates, namely with setting the frequencies of updates.

A sudden change of a certificate on a pinned domain is best resolved by utilizing a [global validation observer](#global-validation-observers). The observer is notified about validation failures. The app can then force updating the fingerprints to resolve the failing TLS handshakes.

Note that failed validation itself doesn't affect the stored fingerprints, an update is necessary to make a change.

## FAQ

### Can the library provide more debug information?

Yes, you can change how much information is printed to the debug console:

```kotlin
WultraDebug.loggingLevel = WultraDebug.WultraLoggingLevel.DEBUG
```

### Is there a dependency on PowerAuthSDK?

There's an optional dependency on [PowerAuthSDK](https://github.com/wultra/powerauth-mobile-sdk). 

This makes the library easier to use with for Wultra customers using our PowerAuthSDK.

In case PowerAuth library is not available, you can't use any class from the `com.wultra.android.sslpinning.integration.powerauth` package since they expect PowerAuthSDK to be present and any such usage will result in an ClassNotFound exception.

### What is pinned?

In SSL pinning there are [two options](https://www.owasp.org/index.php/Certificate_and_Public_Key_Pinning#What_Should_Be_Pinned.3F) of what to pin:

1. **Pin the certificate** (DER encoding)
2. **Pin the public key**

**WultraSSLPinning** tooling (e.g. this Android library, [iOS version](https://github.com/wultra/ssl-pinning-ios) and [Dynamic SSL Pinning Tool](https://github.com/wultra/ssl-pinning-tool)) use the first option: they pin the certificate.

In Java (Android) world this means that the library computes the fingerprint from:

```java
Certificate certificate = ...;
byte[] bytesToComputeFingerprintFrom = certificate.getEncoded();
```

<!-- begin box info -->
Note: Many blog posts and tools for certificate pinning on Android instead mention/use the second option - public key pinning. An example is [CertificatePinner](https://square.github.io/okhttp/3.x/okhttp/okhttp3/CertificatePinner.html) from popular [OkHttp](http://square.github.io/okhttp/) library.
<!-- end -->

In the case of public key pinning, the fingerprint is computed from:

```java
Certificate certificate = ...;
byte[] bytesToComputeFringerprintFrom = certificate.getPublicKey().getEncoded();
```

This means that `CertificatePinner` cannot be readily used with the **WultraSSLPinning** library.

### How to use public key pinning instead of certificate pinning?

If you really want to use public key pinning instead of certificate pinning (e.g. because you are fond of OkHttp's `CertificatePinner`). You have to do a couple of things:

- You need different fingerprints in the update JSON. [Dynamic SSL Pinning Tool](https://github.com/wultra/ssl-pinning-tool) computes only certificate pinning. Therefore you need to generate those fingerprints yourself.
- Don't use these classes/methods (they are bound to certificate pinning):
   - `CertStore.validateCertificate(X509Certificate)`
   - `SSLPinningX509TrustManager`
   - `SSLPinningIntegration.createSSLPinningSocketFactory(CertStore)`
   - `PowerAuthSslPinningValidationStrategy`

You can use `CertStore.validateCertficateData(commonName, byteArray)` only if you pass public key bytes as `byteArray`.

For validating certificates, utilize `CertStore.validateFingerprint()` this way:

```kotlin
fun validateCertWithPublicKeyPinning(certificate: X509Certificate): ValidationResult {
    val key = certificate.publicKey.encoded
    val fingerprint = cryptoProvider.hashSha256(key)
    val commonName = CertUtils.parseCommonName(certificate)
    return validateFingerprint(commonName, fingerprint)
}
```

If you need `SSLSocketFactory`, reimplement `X509TrustManager` using the above `validateCertWithPublicKeyPinning()` method.

### How can I use `OkHttp` to pin only some domains?

If your app connects to both pinned and not pinned domains, then create two instances of OkHttp client.

Use one instance to communicate with the pinned domains. Set it up according to [Integration with OkHttp](#integration-with-okhttp).

Use the second instance to communicate with the domains that are not pinned. Use normal setup for this one, don't use `SSLSocketFactory` and `TrustManager` provided by this library.

### TLS 1.2 Support for older Android versions
   
This library supports TLS 1.2 for older Android versions (API < 21), but in some cases, your app will need to call `ProviderInstaller.installIfNeeded` (part of the Play Services), to install system support.

### Download fingerprints from a test server

If your app connects to the development server with a self-signed certificate, then you can set `SslValidationStrategy.noValidation()` to `sslValidationStrategy` configuration to turn off the certificate chain validation.

Be aware, that using this option will lead to the use of an unsafe implementation of `HostnameVerifier` and `X509TrustManager` SSL client validation. This is useful for debug/testing purposes only, e.g. when an untrusted self-signed SSL certificate is used on the server side.

It's strictly recommended to use this option only in debug flavors of your application. Deploying to production may cause a "Security alert" in the Google Developer Console. Please see [this](https://support.google.com/faqs/answer/7188426) and [this](https://support.google.com/faqs/answer/6346016) Google Help Center articles for more details. Beginning 1 March 2017, Google Play will block the publishing of any new apps or updates that use such unsafe implementation of `HostnameVerifier`.

How to solve this problem for debug/production flavors in Gradle build script:

1. Define a boolean type `buildConfigField` in flavor configuration.

   ```
   productFlavors {
     production {
       buildConfigField 'boolean', 'TRUST_ALL_SSL_HOSTS', 'false'
     }
     debug {
       buildConfigField 'boolean', 'TRUST_ALL_SSL_HOSTS', 'true'
     }
   }
   ```

2. In code use this conditional initialization for [CertStoreConfiguration.Builder]:

   ```kotlin
   val publicKey = Base64.decode("BMne....kdh2ak=", Base64.NO_WRAP)
   val builder = CertStoreConfiguration.Builder(
                    serviceUrl = URL("https://localhost/..."),
                    publicKey = publicKey)
   if (BuildConfig.TRUST_ALL_SSL_HOSTS) {
       builder.sslValidationStrategy(SslValidationStrategy.noValidation())
   }
   val configuration = builder.build()
   ```

3. Set `minifyEnabled` to `true` for release buildType to enable code shrinking with ProGuard.


## License

All sources are licensed using Apache 2.0 license. You can use them with no restrictions. If you are using this library, please let us know. We will be happy to share and promote your project.

## Contact

If you need any assistance, do not hesitate to drop us a line at [hello@wultra.com](mailto:hello@wultra.com) or our official [wultra.com/discord](https://wultra.com/discord) channel.

### Security Disclosure

If you believe you have identified a security vulnerability with WultraSSLPinning, you should report it as soon as possible via email to [support@wultra.com](mailto:support@wultra.com). Please do not post it to a public issue tracker.
