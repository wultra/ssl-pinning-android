# Dynamic SSLK pinning for Android

## Introduction

## Installation

### Requirements

- minSdkVersion 19 (Android 4.4 Kitkat)

## Usage

- `CertStore` - the main class which provides all the library features

## Configuration

```
val configuration = CertStoreConfiguration.Builder(
                            serviceUrl = "https://...", 
                            publicKey = "BMne....kdh2ak=")
                        .build()
val certStore = CertStore(configuration, 
```

### Predefined fingerprint

## Update fingerprints

## Fingerprint validation

## PowerAuth integration

## FAQ

## License

## Contact