# WebAuthn4J Spring Security

[![Actions Status](https://github.com/sharplab/webauthn4j-spring-security/workflows/CI/badge.svg)](https://github.com/sharplab/webauthn4j-spring-security/actions)
<!-- [![Coverage](https://sonarcloud.io/api/project_badges/measure?project=webauthn4j-spring-security&metric=coverage)](https://sonarcloud.io/dashboard?id=webauthn4j-spring-security) -->
[![license](https://img.shields.io/github/license/sharplab/webauthn4j-spring-security.svg)](https://github.com/sharplab/webauthn4j-spring-security/blob/master/LICENSE.txt)

WebAuthn4J Spring Security provides Web Authentication specification support for your Spring application by using WebAuthn4J library.
Users can login with WebAuthn compliant authenticator.

## Project status

This project is under active development. API signature may change.

## Documentation

You can find out more details from the [reference](https://sharplab.github.io/webauthn4j-spring-security/en/).

## Build

WebAuthn4J Spring Security uses a Gradle based build system.
In the instructions below, `gradlew` is invoked from the root of the source tree and serves as a cross-platform,
self-contained bootstrap mechanism for the build.

### Prerequisites

- Java8 or later
- Spring Framework 5.0 or later

### Checkout sources

```
git clone https://github.com/sharplab/webauthn4j-spring-security
```

### Build all jars

```
./gradlew build
```

### Execute sample application

```
./gradlew samples:javaconfig:webauthn:spa:bootRun
```

![Login view](./docs/src/reference/asciidoc/en/images/login.png "Login view")

## License

WebAuthn4J Spring Security is Open Source software released under the
[Apache 2.0 license](http://www.apache.org/licenses/LICENSE-2.0.html).
