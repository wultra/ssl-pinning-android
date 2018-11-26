# Dynamic SSL pinning for Android

`WultraSSLPinning` is an Android library implementing dynamic SSL pinning, written in Kotlin.

- [Introduction](#introduction)
    - [What is pinned](#what-is-pinned)
- [Installation](#installation)
    - [Requirements](#requirements)
    - [Gradle](#gradle)
- [Usage](#usage)
    - [Configuration](#configuration)
        - [Predefined fingerprint](#predefined-fingerprint)
    - [Update fingerprints](#updating-fingerprints)
        - [Checking if update is necessary](#checking-if-update-is-necessary)
        - [Switching server certificate](#switching-server-certificate)
    - [Fingerprint validation](#fingerprint-validation)
        - [Global validation observers](#global-validation-observers)
    - [Integration](#integration)
        - [PowerAuth integration](#powerauth-integration)
        - [PowerAuth integration from Java](#powerauth-integration-from-java)
        - [Integration with HttpsUrlConnection and OkHttp](#integration-with-httpsurlconnection-and-okhttp)
- [FAQ](#faq)
- [License](#license)
- [Contact](#contact)
    - [Security Disclosure](#security-disclosure)

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

### What is pinned

In SSL pinning there are [two options](https://www.owasp.org/index.php/Certificate_and_Public_Key_Pinning#What_Should_Be_Pinned.3F) of what to pin:
1. **Pin the certificate** (DER encoding)
2. **Pin the public key**

**WultraSSLpinning** tooling ([this Android version](https://github.com/wultra/ssl-pinning-android),
[iOS version](https://github.com/wultra/ssl-pinning-ios)
and [Dynamic SSL Pinning Tool](https://github.com/wultra/ssl-pinning-tool))
use *option 1 - they pin the certificate*.

In Java (Android) world this means that the library computes the fingerprint
from:
```java
Certificate certificate = …
byte[] bytesToComputeFringerprintFrom = certificate.getEncoded()
```

Note: Many blog posts and tools for certificate pinning on Android instead mention/use option 2 - public key pinning.
An example is [CertificatePinner](https://square.github.io/okhttp/3.x/okhttp/okhttp3/CertificatePinner.html)
from popular [OkHttp](http://square.github.io/okhttp/) library.

In case of public key pinning the fingerprint is computed from:
```java
Certificate certificate = …
byte[] bytesToComputeFringerprintFrom = certificate.getPublicKey().getEncoded()
```

This means that `CertificatePinner` cannot be readily used with **WultraSSLPinning** library.


## Installation


### Requirements

- minSdkVersion 16 (Android 4.1 Jelly Bean)

### Gradle

To use **WultraSSLPinning** in you Android app add this dependency:

```gradle
implementation 'com.wultra.android.sslpinning:wultra-ssl-pinning:0.8.1'
```

Also make sure you have `jcenter()` repository among the project repositories.


## Usage

- `CertStore` - the main class which provides all the library features
- `CertStoreConfiguration` - the configuration class for `CertStore` class

The next chapters of this document will explain how to configure and use `CertStore` for the SSL pinning purposes.

## Configuration

An example for `CertStore` configuration in Kotlin:

```kotlin
val publicKey: ByteArray
val configuration = CertStoreConfiguration.Builder(
                            serviceUrl = URL("https://…"), 
                            publicKey = publicKey)
                        .identifier(identifier)
                        .expectedCommonNames(expectedCommonNames)
                        .fallbackCertificate(fallbackCertificate)
                        .build()
val certStore = CertStore(configuration, cryptoProvider, secureDataStore)
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


### Predefined fingerprint

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


## Updating fingerprints

To update the list of fingerprints from the remote server, use the following code:

```kotlin
val updateStarted = certStore.update(updateMode, updateObserver)
```

The method is asynchronous. It returns boolean value. True signifies that the udpate is has been started,
false means that the method internally decided that update is not necessary based on
the cached data and input parameters.
Result of the udpate is returned in `UpdateObserver` passed as a second argument.
It is notified on the main thread.
The observer is optional. Update can be called this way:
```java
boolean updateStarted = certStore.update(updateMode)
```

The app (not the library) is responsible for invoking updates.
If the update is not forced the library does the actual update only
if the stored fingerprints are expired or about to expire.

The app has to typically call the update during the application's startup, 
before a secure HTTPS request is initiated to a server that's supposed to be validated with the pinning. 

The update function works in two basic modes:

- **Forced mode**, this happens when the mode is forced (`UpdateMode.FORCED`).
- **Default mode**, this mode does internal evaluation of the stored data and configuration
and tries to avoid unnecessary downloads when the data are ok.
Note that the method does not evaluate whether the cert on the server endpoints was updated.
The frequency of default update is predefined and determined by the configuration and currently stored data (fingerprints).

The both updates are performed on an `ExecutorService` defined in the configuration,
if not defined, the update run on a dedicated thread.

### Checking if update is necessary

To check if udpate is needed based on the stored data and configuration,
there is `certStore.checkUpdateNeeded()` method.

If the method returns true, update would be performed even when not forced.
Otherwise default update mode would omit the update.

### Switching server certificate

Certificate pinning is great for your app's security and at the same time
it's a very dangerous technology.
Be careful with the update parameters in `CertStoreConfiguration` serving for default updates.

Sudden change of a certificate on a pinned domain is best resolved by utilizing
a [global validation observer](#global-validation-observers). The observer
is notified about validation failures. The app can then
force update the fingerprints to resolve the failing TLS handshakes.

## Fingerprint validation

The `CertStore` provides several methods for certificate fingerprint validation. 
You can choose the one which suits best your scenario:

```kotlin
// [ 1 ]  If you already have the common name (e.g. domain) and certificate fingerprint

val commonName = "yourdomain.com"
val fingerprint: ByteArray = …
val validationResult = certStore.validateFingerprint(commonName, fingerprint)

// [ 2 ]  If you already have the common name and the certificate data (in DER format)
val commonName = "yourdomain.com"
val certData: ByteArray = …
val validationResult = certStore.validateCertificateData(commonName, certData)

// [ 3 ]  You want to validate java.security.cert.X509Certificate
val certificate: java.security.cert.X509Certificate = connection.getServerCertificates()[0]
val validationResult = certStore.validateCertificate(certificate)
```

Each `validate…` method returns `ValidationResult` enum with following options:

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

### Global validation observers

In order to be notified about all validation failures there is `ValidationObserver`
interface and methods on `CertStore` for adding/removing global validation observers.

Motivation for these global validation observers is that some validation failures
(e.g. those happening in `SSLSocketFactory` instances created by `SSLSocketIntegration.createSSLPinningSocketFactory(CertStore)`)
are out of reach of the app integrating the pinning library.
These global validation observers are notified about all validation failures.
The app can then react with force updating the fingerprints.

## Integration

### PowerAuth integration

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

### PowerAuth integration from Java

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
Call this in Java is too cumbersome: `PowerAuthIntegrationKt.powerAuthCertStore(CertStore.Companion, configuration, context, null)`.

### Integration with HttpsUrlConnection and OkHttp

For integration with HttpsUrlConnection or [OkHttp](http://square.github.io/okhttp/)
use classes `SSLPinningIntegration` and `SSLPinningX509TrustManager`.
These provide the necessary `SSLSocketFactory` and `X509TrustManager`.


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

---

## License

All sources are licensed using Apache 2.0 license. You can use them with no restriction. 
If you are using this library, please let us know. We will be happy to share and promote your project.

## Contact

If you need any assistance, do not hesitate to drop us a line at hello@wultra.com 
or our official [gitter.im/wultra](https://gitter.im/wultra) channel.

### Security Disclosure

If you believe you have identified a security vulnerability with WultraSSLPinning, 
you should report it as soon as possible via email to support@wultra.com. Please do not post it to a public issue tracker.
