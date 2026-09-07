# Copilot Instructions — ssl-pinning-android

## Project Overview

`WultraSSLPinning` is an Android library implementing **dynamic SSL pinning**. Instead of bundling static certificate hashes, it securely downloads a signed list of certificate fingerprints from a remote server ([Mobile Utility Server](https://github.com/wultra/mobile-utility-server)). All fingerprints are signed with ECDSA-SHA-256 and verified locally using a public key embedded at build time.

## Build, Test, and Lint Commands

Requires **JDK 17** and Android SDK.

```bash
# Build
./gradlew library:assemble

# Unit tests (JVM, no device needed)
./gradlew library:test

# Run a single unit test class
./gradlew library:test --tests "com.wultra.android.sslpinning.CertStoreUpdateTest"

# Run a single test method
./gradlew library:test --tests "com.wultra.android.sslpinning.CertStoreUpdateTest.testCorrectUpdate"

# Lint
./gradlew library:lint

# Instrumentation tests (requires connected emulator/device)
./gradlew library:connectedAndroidTest

# Clean
./gradlew clean
```

Instrumentation tests that hit a real server (`CertStoreNetworkTest`) require credentials configured in `configs/integration-tests.properties` (or `configs/private-integration-tests.properties`). See `scripts/prepare-tests.sh` for setup.

## Architecture

The project has a single Gradle module: `:library`. The `pinningtool/` directory is a standalone CLI JAR tool, not a Gradle subproject.

### Core classes

| Class | Role |
|---|---|
| `CertStore` | Main entry point; manages fingerprint cache, update scheduling, and certificate validation |
| `CertStoreConfiguration` | Builder-pattern configuration (service URL, public key, expected common names, fallback certs) |
| `ValidationResult` | Result of a TLS handshake check (`trusted`, `untrusted`, `empty`) |
| `UpdateResult` | Outcome of a remote fingerprint fetch (`ok`, `networkError`, `invalidSignature`, etc.) |

### Pluggable interfaces

`CertStore` is constructed with two swappable interfaces:
- **`CryptoProvider`** — ECDSA signature validation, SHA-256, EC key import
- **`SecureDataStore`** — persistent encrypted storage (load/save/remove by key)

Default implementations (`DefaultCryptoProvider`, `DefaultSecureDataStore`) use Android's built-in crypto and `EncryptedSharedPreferences` respectively.

### Data flow

1. `CertStore.update()` calls `RemoteDataProvider.getFingerprints()` (implemented by `RestApi`)
2. The challenge-response protocol uses `X-Cert-Pinning-Challenge` (request) and `x-cert-pinning-signature` (response) headers
3. `CertStore` validates the ECDSA signature on the response body via `CryptoProvider`
4. Valid data is serialised as JSON via GSON and persisted through `SecureDataStore`; the cached model is `CachedData`
5. Fingerprint expiry is monitored by `UpdateScheduler` to trigger more frequent updates near expiry

### Domain bypass

The server can include a `DomainsConfig` in its response, allowing selective bypass of SSL pinning for specific domains. `DomainsConfig.isPinningRequired(commonName)` checks per-domain config first, then falls back to a global `sslPinningRequiredForUnlisted` flag. This config is persisted as part of `CachedData`.

### Validation observers

`CertStore` supports registering `ValidationObserver` instances that receive callbacks (`onValidationTrusted`, `onValidationUntrusted`, `onValidationEmpty`) on the main thread for every certificate validation. Useful for analytics and debugging.

### Integration points

- **`SSLPinningIntegration`** — helpers for `HttpsURLConnection` and OkHttp
- **`SSLPinningX509TrustManager`** — drops into any `SSLContext`

## Key Conventions

### Build constants
All SDK/version constants live in `buildSrc/src/main/kotlin/Constants.kt`. Update versions there; they are consumed by both `buildSrc/build.gradle.kts` and `library/build.gradle.kts` via `System.getProperties()`.

### `CertStore` constructor pattern
The primary `internal` constructor takes `(configuration, cryptoProvider, secureDataStore, remoteDataProvider?)` and is used by tests to inject mocks. The two public constructors (`context`-only and `cryptoProvider + secureDataStore`) are for production use.

### Test structure
- **Unit tests** (`src/test`) — JVM-only; use MockK. Extend `CommonKotlinTest` which:
  - mocks `android.util.Base64`, `android.util.Log`, `Looper`
  - installs BouncyCastle as a JCE provider
  - uses a mocked `CryptoProvider` and default JCA/ECDSA validation for selected operations
- **Instrumentation tests** (`src/androidTest`) — require a device/emulator and optionally a live Mobile Utility Server
- Async update calls in tests are coordinated with `CountDownLatch` + `UpdateObserver`

### Logging
Use `WultraDebug.info/warning/error()` — never `android.util.Log` directly. The log tag is `"Wultra-SSL-Pinning"`. Default level is `RELEASE`; set `WultraDebug.loggingLevel = WultraDebug.WultraLoggingLevel.DEBUG` to enable verbose output.

### Network
`RestApi` uses plain `HttpURLConnection` (no OkHttp in the library itself). Response header names are lowercased with `Locale.getDefault()` before storage/lookup to handle case variations.

### File headers
All source files carry an Apache 2.0 copyright header for `Wultra s.r.o.`
