# Dynamic SSL pinning for Android
<!-- begin remove -->
`WultraSSLPinning` is an Android library implementing dynamic SSL pinning, written in Kotlin.
<!-- end -->
<!-- begin TOC -->
- [Introduction](#introduction)
- [Installation](#installation)
    - [Requirements](#requirements)
    - [Gradle](#gradle)
- [Usage](#usage)
    - [Configuration](#configuration)
        - [Predefined Fingerprint](#predefined-fingerprint)
    - [Update Fingerprints](#updating-fingerprints)
    - [Fingerprint Validation](#fingerprint-validation)
        - [Global Validation Observers](#global-validation-observers)
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

## Introduction

The SSL pinning (or [public key, or certificate pinning](https://en.wikipedia.org/wiki/Transport_Layer_Security#Certificate_pinning)) 
is a technique mitigating [Man-in-the-middle attacks](https://en.wikipedia.org/wiki/Man-in-the-middle_attack) against the secure HTTPS communication. 

The typical Android solution is to bundle the hash of the certificate,
or the exact data of the certificate into the application.
The connection is then validated via `X509TrustManager`.
Popular `OkHttp` library has built in `CertificatePinner` class that simplifies the integration.

In general, this works well, but it has, unfortunately, one major drawback in the certificate's expiration date.
The certificate expiration forces you to update your application regularly before the certificate expires.
Unfortunatelly, some percentage of users don't update their apps automatically.
In effect, users on older versions, will not be able to contact the application servers.

A solution to this problem is the **dynamic SSL pinning**,
where the list of certificate fingerprints is securely downloaded from the remote server.

`WultraSSLPinning` library does precisely this:

- Manages the dynamic list of certificates, downloaded from the remote server.
- All entries in the list are signed with your private key and validated in the library using the public key (we're using ECDSA-SHA-256 algorithm)
- Provides easy to use fingerprint validation on the TLS handshake.

Before you start using the library, you should also check our other related projects:

- [Dynamic SSL Pinning Tool](https://github.com/wultra/ssl-pinning-tool) - the command line tool written in Java, for generating update JSON data consumed by this library.
- [iOS version](https://github.com/wultra/ssl-pinning-ios) of the library

## Installation

### Requirements

- minSdkVersion 16 (Android 4.1 Jelly Bean)

### Gradle

To use **WultraSSLPinning** in you Android app add this dependency:

```gradle
implementation 'com.wultra.android.sslpinning:wultra-ssl-pinning:1.0.0'
```

Note that this documentation is using version `1.0.0` as an example. You can find the latest version at [github's release](https://github.com/wultra/ssl-pinning-android/releases#docucheck-keep-link) page. The Android Studio IDE can also find and offer updates for your application’s dependencies.

Also make sure you have `jcenter()` repository among the project repositories.

## Usage

- `CertStore` - the main class which provides all the library features
- `CertStoreConfiguration` - the configuration class for `CertStore` class

The next chapters of this document will explain how to configure and use `CertStore` for the SSL pinning purposes.

### Configuration

An example for `CertStore` configuration in Kotlin:

```kotlin
val publicKey: ByteArray = Base64.decode("BMne....kdh2ak=", Base64.NO_WRAP)
val configuration = CertStoreConfiguration.Builder(
                            serviceUrl = URL("https://..."), 
                            publicKey = publicKey)
                        .identifier(identifier)
                        .expectedCommonNames(expectedCommonNames)
                        .fallbackCertificate(fallbackCertificate)
                        .build()
val certStore = CertStore.powerAuthCertStore(configuration = configuration, appContext)
```

The configuration has the following properties:

- `serviceUrl` - parameter defining URL with a remote list of certificates (JSON).
- `publicKey` - byte array containing the public key counterpart to the private key, used for fingerprint signing.
- `expectedCommonNames` - an optional array of strings, defining which domains you expect in certificate validation.
- `identifier` - optional string identifier for scenarios, where multiple `CertStore` instances are used in the application.
- `fallbackCertificateData` - optional hardcoded data for a fallback fingerprint. See the next chapter of this document for details.
- `periodicUpdateIntervalMillis` - defines interval for default updates. The default value is 1 week.
- `expirationUpdateTreshold` - defines time window before the next certificate will expire. 
In this time window `CertStore` will try to update the list of fingerprints more often than usual. 
Default value is 2 weeks before the next expiration.
- `executorService` - defines `java.util.concurrent.ExecutorService` for running updates.
If not defined updates run on a dedicated thread (not pooled).

### Predefined Fingerprint

The `CertStoreConfiguration` may contain an optional data with predefined certificate fingerprint. 
This technique can speed up the first application's startup when the database of fingerprints is empty. 
You still need to [update](#updating-fingerprints) your application, once the fallback fingerprint expires.

To configure the property, you need to provide `GetFingerprintResponse.Entry` with a fallback certificate fingerprint. 
The data should contain the same data as are usually received from the server, 
except that `signature` property is not validated (but must be provided). For example:

```kotlin
val fallbackData = GetFingerprintResponse.Entry(
                       name = "github.com",
                       fingerprint = fingerprintBytes,
                       expires new Date(1591185600000),
                       ByteArray(0))
val configuration = CertStoreConfiguration.Builder(
                            serviceUrl = URL("https://..."),
                            publicKey= publicKey)
                    .fallbackCertificateData(fallbackData)
                    .build()
val certStore = CertStore.powerAuthCertStore(configuration = configuration, appContext)
```

## Updating Fingerprints

To update the list of fingerprints from the remote server, use the following code:

```kotlin
certStore.update(UpdateMode.DEFAULT, UpdateMode.DEFAULT, object : DefaultUpdateObserver() {
    override fun continueExecution() {
        // Certstore is likely up-to-date, you can resume execution of your code.
    }

    override fun handleFailedUpdate(type: UpdateType, result: UpdateResult) {
        // There was an error during the update, present an error to the user.
    }

})
```

The method is asynchronous. `DefaultUpdateObserver` has two callbacks:

- `continueExecution()` tells you that the certstore likely contains up-to-date data and your application should continue with the flow.
- `handleFailedUpdate(UpdateType, UpdateResult)` tells you that there was an error during the update execution you should handle.

Both callbacks are notified on the main thread.

`DefaultUpdateObserver` is the default implementation of `UpdateObserver`. In case you need more control over the flow, you can use the interface directly:

```kotlin
certStore.update(UpdateMode.DEFAULT, UpdateMode.DEFAULT, object : UpdateObserver() {
    override fun onUpdateStarted(type: UpdateType) {
        // Certstore update started, either in DIRECT, SILENT or NO_UPDATE mode 
    }

    override fun onUpdateFinished(type: UpdateType, result: UpdateResult) {
        // Certstore update of a given type finished asynchronously with some result.
    }

})
```

The method is asynchronous. `UpdateObserver` has two callbacks:

- `onUpdateStarted(UpdateType)` tells you what type of update has been started
- `onUpdateFinished(UpdateType, UpdateResult)` tells you the result and type of the update

Both callbacks are notified on the main thread.

There are three update types:

- `UpdateType.DIRECT` - The update is either **forced** or the
library is missing essential data (fingerprints). The app is not advised to continue
until the update is finished because there's a high risk of failing network requests
due to server certificates evaluated as untrusted.
- `UpdateType.SILENT` - The update is not critical but will be performed.
The library has data but the data are going to expire soon. There's low risk
of failing network requests due to server certificates evaluated as untrusted.
- `UpdateType.NO_UPDATE` - No update will be performed. The library
has data and they are not going to expire soon. There's low risk
of failing network requests due to server certificates evaluated as untrusted.

The update function works in two basic modes:

- **Forced mode**, this happens when the mode is forced (`UpdateMode.FORCED`).
- **Default mode**, this mode does internal evaluation of the stored data and configuration
and tries to avoid unnecessary downloads when the data are ok.

_Note: In any update type, there's still a risk of failing network requests
due to server certificates evaluated as untrusted. This is due to the fact
that server certificate might be replaced at any time and the library might
not be aware of it yet. To mitigate this cases it's recommended to implement
a [global validation observer](#global-validation-observers)._

Updates are performed on an `ExecutorService` defined in the configuration,
if not defined, the update run on a dedicated thread.

Note that your app is responsible for invoking the update method.
The app typically has to call the update during the application's startup,
before the first secure HTTPS request is initiated to a server that's supposed
to be validated with the pinning.

## Fingerprint Validation

The `CertStore` provides several methods for certificate fingerprint validation. 
You can choose the one which suits best your scenario:

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
```

Each `validate...` method returns `ValidationResult` enum with following options:

- `ValidationResult.TRUSTED` - the server certificate is trusted. You can continue with the connection

  The right response in this situation is to continue with the ongoing communication.
   
- `ValidationResult.UNTRUSTED` - the server certificate is not trusted. You should cancel the ongoing connection.

  The untrusted result means that `CertStore` has some fingerprints stored in its
  database, but none matches the value you requested for validation. The right
  response on this situation is always to cancel the ongoing connection.

- `ValidationResult.EMPTY` - the fingerprint database is empty, or there's no fingerprint for the validated common name.

  The "empty" validation result typically means that the `CertStore` should update
  the list of certificates immediately. Before you do this, you should check whether
  the requested common name is what you're expecting. To simplify this step, you can set 
  the list of expected common names in the `CertStoreConfiguration` and treat all others as untrusted.
    
  For all situations, the right response in this situation is always to cancel the ongoing
  connection.


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

In order to be notified about all validation failures there is `ValidationObserver`
interface and methods on `CertStore` for adding/removing global validation observers.

Motivation for these global validation observers is that some validation failures
(e.g. those happening in `SSLSocketFactory` instances created by `SSLSocketIntegration.createSSLPinningSocketFactory(CertStore)`)
are out of reach of the app integrating the pinning library.
These global validation observers are notified about all validation failures.
The app can then react with force updating the fingerprints.

## Integration

### PowerAuth Integration

The **WultraSSLPinning** library contains classes for integration with the PowerAuth SDK.
The most important one is the `PowerAuthSslPinningValidationStrategy` class, 
which implements `PA2ClientValidationStrategy` with SSL pinning. 
You can simply instantiate in with an existing `CertStore` and set it in `PA2ClientConfiguration`. 
Then the class will provide SSL pinning for all communication initiated within the PowerAuth SDK.

For example, this is how the configuration sequence may look like if you want to use both, `PowerAuthSDK` and `CertStore`:

```kotlin
val certStoreConfiguration = CertStoreConfiguration.Builder(
                            serviceUrl = URL("https://..."),
                            publicKey= publicKey)
                    .fallbackCertificateData(fallbackData)
                    .build()
                    
val powerAuthCertStore = CertStore.powerAuthCertStore(certStoreConfiguration, appContext)


val powerAuthConfiguration = PowerAuthConfiguration.Builder(
                appContext.packageName,
                BuildConfig.PA_API_SERVER,
                BuildConfig.PA_APPLICATION_KEY,
                BuildConfig.PA_APPLICATION_SECRET,
                BuildConfig.PA_MASTER_SERVER_PUBLIC_KEY
            ).build()

val powerAuthClientConfiguration = PowerAuthClientConfiguration.Builder()
                .clientValidationStrategy(sslPinningValidationStrategy)
                .allowUnsecuredConnection(false)
                .build()
                
val powerAuth = PowerAuthSDK.Builder(powerAuthConfiguration)
                .clientContifuration(powerAuthClientConfiguration)
                .build(appContext)
```

### PowerAuth Integration From Java

Some of the Kotlin's PowerAuthSDK integration APIs are inconvenient in Java.
A `CertStore` integrating PowerAuthSDK can be created with:

```java
CertStore store = PowerAuthCertStore.createInstance(configuration, context);
```

or

```java
CertStore store = PowerAuthCertStore.createInstance(configuration, context, "my-keychain-identifier");
```

Note that Kotlin's way of construction `CertStore.powerAuthCertStore` is not available in Java.
Calling this in Java would be way too cumbersome, but will work:

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

 To integrate with OkHttp, use following code:
 
```kotlin
val sslSocketFactory = SSLPinningIntegration.createSSLPinningSocketFactory(certStore);
val trustManager = SSLPinningX509TrustManager(certStore)

val okhttpClient = OkHttpClient.Builder()
                .sslSocketFactory(sslSocketFactory, trustManager)
                .build()
```

In the code above, use `SSLSocketFactory` provided by `SSLPinningIntegration.createSSLPinningSocketFactory(...)`
and an instance of `SSLPinningX509TrustManager`.

## Switching Server Certificate

Certificate pinning is great for your app's security but at the same time, it requires
care when deploying it to your customers.
Be careful with the update parameters in `CertStoreConfiguration` serving for the default
updates, namely with setting the frequencies of update.

Sudden change of a certificate on a pinned domain is best resolved by utilizing
a [global validation observer](#global-validation-observers). The observer
is notified about validation failures. The app can then
force updating the fingerprints to resolve the failing TLS handshakes.

Note that failed validation itself doesn't affect the stored fingerprints,
update is necessary to make a change.

## FAQ

### Can the library provide more debug information?

Yes, you can change how much information is printed to the debug console:

```kotlin
WultraDebug.loggingLevel = WultraLoggingLevel.RELEASE
```

### Is there a dependency on PowerAuthSDK?

There's an optional dependency on [PowerAuthSDK](https://github.com/wultra/powerauth-mobile-sdk). 

However, the library requires several cryptographic primitives (see `CryptoProvider`)
that are provided by **PowerAuthSDK**. 
Also most of our clients are already using PowerAuthSDK in their applications. 
Therefore it's a non-brainer to use **PowerAuthSDK** for the cryptography in **WultraSSLPinning**.

If needed the library can be used without PowerAuthSDK. 
In this case you can't use any class from `com.wultra.android.sslpinning.integration.powerauth` package
since they expect PowerAuthSDK to be present.
Also you have to provide you own implementation of `CryptoProvider` and `SecureDataStore`.

### What is pinned?

In SSL pinning there are [two options](https://www.owasp.org/index.php/Certificate_and_Public_Key_Pinning#What_Should_Be_Pinned.3F) of what to pin:

1. **Pin the certificate** (DER encoding)
2. **Pin the public key**

**WultraSSLpinning** tooling (e.g. this Android library,
[iOS version](https://github.com/wultra/ssl-pinning-ios) and
[Dynamic SSL Pinning Tool](https://github.com/wultra/ssl-pinning-tool)) use *option 1: they pin the certificate*.

In Java (Android) world this means that the library computes the fingerprint
from:

```java
Certificate certificate = ...;
byte[] bytesToComputeFringerprintFrom = certificate.getEncoded();
```

Note: Many blog posts and tools for certificate pinning on Android instead mention/use option 2 - public key pinning.
An example is [CertificatePinner](https://square.github.io/okhttp/3.x/okhttp/okhttp3/CertificatePinner.html)
from popular [OkHttp](http://square.github.io/okhttp/) library.

In case of public key pinning the fingerprint is computed from:

```java
Certificate certificate = ...;
byte[] bytesToComputeFringerprintFrom = certificate.getPublicKey().getEncoded();
```

This means that `CertificatePinner` cannot be readily used with **WultraSSLPinning** library.


**PowerAuthSDK** already provides these functions.

If you do not desire to integrate PowerAuthSDK you can implement necessary interfaces yourself.
The core of the library is using `CryptoProvider` and `SecureDataStore` interfaces and therefore is implementation independent.


### How to use public key pinning instead of certificate pinning?

If you really want to use public key pinning instead of certificate pinning
(e.g. because you are fond of OkHttp's `CertificatePinner`).
You have to do couple of things:

* You need different fingerprints in the update json.
[Dynamic SSL Pinning Tool](https://github.com/wultra/ssl-pinning-tool)
computes only certificate pinning. Therefore you need to generate those
fingerprints yourself.
* Don't use these classes/methods (they are bound to certificate pinning):
   * `CertStore.validateCertificate(X509Certificate)`
   * `SSLPinningX509TrustManager`
   * `SSLPinningIntegration.createSSLPinningSocketFactory(CertStore)`
   * `PowerAuthSslPinningValidationStrategy`

You can use `CertStore.validateCertficateData(commonName, byteArray)`
only if you pass public key bytes as `byteArray`.

For validating certificates, utilize `CertStore.validateFingerprint()` this way:
```kotlin
fun validateCertWithPublicKeyPinning(certificate: X509Certificate): ValidationResult {
    val key = certificate.publicKey.encoded
    val fingerprint = cryptoProvider.hashSha256(key)
    val commonName = CertUtils.parseCommonName(certificate)
    return validateFingerprint(commonName, fingerprint)
}
```

If you need `SSLSocketFactory`, reimplement `X509TrustManager`
using the above `validateCertWithPublicKeyPinning()` method.

### How can I use `OkHttp` to pin only some domains?

If your app connects to both pinned and not pinned domains, then
create two instances of OkHttp client.

Use one instance to communicate with the pinned domains. Set it up according to [Integration with OkHttp](#integration-with-okhttp).

Use the second instance to communicate with the domains that are not pinned.
Use normal setup for this one, don't use `SSLSocketFactory` and `TrustManager` provided by this library.

## License

All sources are licensed using Apache 2.0 license. You can use them with no restriction. 
If you are using this library, please let us know. We will be happy to share and promote your project.

## Contact

If you need any assistance, do not hesitate to drop us a line at [hello@wultra.com](mailto:hello@wultra.com) 
or our official [gitter.im/wultra](https://gitter.im/wultra) channel.

### Security Disclosure

If you believe you have identified a security vulnerability with WultraSSLPinning, 
you should report it as soon as possible via email to [support@wultra.com](mailto:support@wultra.com). Please do not post it to a public issue tracker.
