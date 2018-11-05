# Dynamic SSL pinning for Android

`WultraSSLPinning` is an Android library implementing dynamic SSL pinning, written in Kotlin.

- [Introduction](#introduction)
- [Installation](#installation)
    - [Requirements](#requirements)
    - [Gradle](#gradle)
- [Usage](#usage)
    - [Configuration](#configuration)
    - [Update fingerprints](#update-fingerprints)
    - [Fingerprint validation](#fingerprint-validation)
    - [PowerAuth integration](#powerauth-integration)
- [FAQ](#faq)
- [License](#license)
- [Contact](#contact)

## Introduction

The SSL pinning (or [public key, or certificate pinning](https://en.wikipedia.org/wiki/Transport_Layer_Security#Certificate_pinning)) 
is a technique mitigating [Man-in-the-middle attacks](https://en.wikipedia.org/wiki/Man-in-the-middle_attack) against the secure HTTPS communication. 
The typical Android solution is to bundle the hash of the certificate, 
or the exact data of the certificate to the application.
The connection is then validated via `X509TrustManager`. 
Popular `OkHttp` library has built in `CertificatePinner` class that simplifies the integration.
In general, this works well, but it has, unfortunately, one major drawback of the certificate's expiration date. 
The certificate expiration forces you to update your application regularly before the certificate expires, 
but still, some percentage of the users don't update their apps automatically. 
So, the users on the older version, will not be able to contact the application servers.

The solution to this problem is the **dynamic SSL pinning**, 
where the list of certificate fingerprints are securely downloaded from the remote server. 

`WultraSSLPinning` library does precisely this:

- Manages the dynamic list of certificates, downloaded from the remote server
- All entries in the list are signed with your private key and validated in the library using the public key (we're using ECDSA-SHA-256 algorithm)
- Provides easy to use fingerprint validation on the TLS handshake.

Before you start using the library, you should also check our other related projects:

- [Dynamic SSL Pinning Tool](https://github.com/wultra/ssl-pinning-tool) - the command line tool written in Java, for generating JSON data consumed by this library.
- [iOS version](https://github.com/wultra/ssl-pinning-ios) of the library


## Installation


### Requirements

- minSdkVersion 16 (Android 4.1 Jelly Bean)

### Gradle

To use **WultraSSLPinning** in you Android app.
Add this depencency:

```gradle
implementation 'com.wultra.android.sslpinning:wultra-ssl-pinning:0.7.1'
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

- `serviceUrl` - parameter defining URL with a remote list of certificates. 
It is recommended that `serviceUrl` points to a different domain than you're going to protect with pinning. 
See the [FAQ](#faq) section for more details.
- `publicKey` - byte array containing the public key counterpart to the private key, used for data signing. 
- `expectedCommonNames` - an optional array of strings, defining which domains you expect in certificate validation.
- `identifier` - optional string identifier for scenarios, where multiple `CertStore` instances are used in the application
- `fallbackCertificateData` - optional hardcoded data for a fallback fingerprint. See the next chapter of this document for details.
- `periodicUpdateIntervalMillis` - defines interval for silent updates. The default value is 1 week.
- `expirationUpdateTreshold` - defines time window before the next certificate will expire. 
In this time window `CertStore` will try to update the list of fingerprints more often than usual. 
Default value is 2 weeks before the next expiration.
- `executorService` - defines `java.util.concurrent.ExecutorService` for running silent updates.
If not defined silent updates run on a dedicated thread (not pooled).


### Predefined fingerprint

The `CertStoreConfiguration` may contain an optional data with predefined certificate fingerprint. 
This technique can speed up the first application's startup when the database of fingerprints is empty. 
You still need to update your application, once the fallback fingerprint expires. 

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


## Update fingerprints

To update list of fingerprints from the remote server, use the following code:

```kotlin
val updateResult = certStore.update()
```

The app (not the library) is responsible for invoking updates. The library only makes sure
that the update is run when necessary.

The app has to typically call the update during the application's startup, 
before a secure HTTPS request is initiated to a server that's supposed to be validated with the pinning. 

The update function works in two basic modes:

- **Blocking mode**, when your application has to wait for downloading the list of certificates.
This typically happens when all certificate fingerprints did expire, 
or during the application's first start (e.g. there's no list of certificates)
In such case the call to `certStore.update()` is blocking. Therefore it should be run on a worker thread.
- **Silent update mode**, the execution of the update is handled on a background thread.
and `update()` method does not block the thread, it returns immedieately with result `UpdateResult.SCHEDULED`.
The purpose of the silent update is to avoid blocking the app's startup while keeping the list of fingerprints up to date. 

If the update is called more often then the value that's predefined and determined by the configuration.
The update returns immediately with `UpdateResult.OK` and no update is permformed. 

The silent update is performed on an `ExecutorService` defined in the configuration,
if not defined the update run on its own dedicated thread.

The direct update (blocking mode) runs on the thread the method is invoked on.


## Fingerprint validation

The `CertStore` provides several methods for certificate fingerprint validation. 
You can choose the one which suits best for your scenario:

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


## PowerAuth integration

The WultraSSLPinning library contains classes for integration with the PowerAuth SDK. 
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
                    
val powerAuthCertStore = CertStore.powerAuthCertStore(certStoreConfiguration)


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

---

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
In this case you can't use any class from `com.wultra.android.sslpinning.powerauth` package
since they expect PowerAuthSDK to be present.
Also you have to provide you own implementation of `CryptoProvider` and `SecureDataStore`.


**PowerAuthSDK** already provides these functions.

But not everything is lost. The core of the library is using `CryptoProvider` protocol and therefore is implementation independent. We'll provide the standalone version of the pinning library later. 



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
