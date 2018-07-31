# Spring Security WebAuthn

[![Build Status](https://travis-ci.org/ynojima/spring-security-webauthn.svg?branch=master)](https://travis-ci.org/ynojima/spring-security-webauthn)
[![Coverage](https://sonarcloud.io/api/project_badges/measure?project=spring-security-webauthn&metric=coverage)](https://sonarcloud.io/dashboard?id=spring-security-webauthn)
[![license](https://img.shields.io/github/license/ynojima/spring-security-webauthn.svg)](https://github.com/ynojima/spring-security-webauthn/blob/master/LICENSE.txt)


Spring Security WebAuthn provides Web Authentication specification support for your Spring application.
Users can login with WebAuthn compliant authenticator.

**This library is intended to be merged into [Spring-Security](https://github.com/spring-projects/spring-security) 
as a pull-request. Package name will be changed when it is remade into the pull-request. This library itself is 
feature-complete, but is not for production use for now as it depends on customized Spring-Security build.**

## Documentation

You can find out more details from the [reference](https://ynojima.github.io/spring-security-webauthn/en/).

## Build

Spring Security WebAuthn uses a Gradle based build system.
In the instructions below, `gradlew` is invoked from the root of the source tree and serves as a cross-platform,
self-contained bootstrap mechanism for the build.

### Prerequisites

- Java8 or later
- Spring Framework 5.0 or later
- Spring Security 5.0 (Customized build)

To support multi factor authentication flow, spring-security-webauthn requires modification to spring-security.
The modification will be sent to spring-security project as a pull-request by the spring-security-webauthn becomes stable, 
but for now, not available with normal spring-security.

### Checkout sources

```
git clone https://github.com/ynojima/spring-security-webauthn
```

### Build all jars

```
./gradlew build
```

### Execute sample application

```
./gradlew spring-security-webauthn-sample:bootRun
```

![Login view](./docs/src/reference/asciidoc/en/images/login.png "Login view")

## License

Spring Security WebAuthn is Open Source software released under the
[Apache 2.0 license](http://www.apache.org/licenses/LICENSE-2.0.html).
