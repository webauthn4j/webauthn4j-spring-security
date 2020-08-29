# WebAuthn4J Spring Security

[![Actions Status](https://github.com/webauthn4j/webauthn4j-spring-security/workflows/CI/badge.svg)](https://github.com/webauthn4j/webauthn4j-spring-security/actions)
[![Coverage](https://sonarcloud.io/api/project_badges/measure?project=webauthn4j-spring-security&metric=coverage)](https://sonarcloud.io/dashboard?id=webauthn4j-spring-security)
[![license](https://img.shields.io/github/license/webauthn4j/webauthn4j-spring-security.svg)](https://github.com/webauthn4j/webauthn4j-spring-security/blob/master/LICENSE.txt)

WebAuthn4J Spring Security provides [Web Authentication specification](https://www.w3.org/TR/2019/REC-webauthn-1-20190304/) support for your Spring application by using [WebAuthn4J library](https://github.com/webauthn4j/webauthn4j).
Users can login with WebAuthn compliant authenticator.

## Project status

This project is under active development. API signature may change.

## Documentation

You can find out more details from the [reference](https://webauthn4j.github.io/webauthn4j-spring-security/en/).

## Getting from Maven Central

If you are using Maven, just add the webauthn4j-spring-security as a dependency:

```xml
<properties>
  ...
  <!-- Use the latest version whenever possible. -->
  <webauthn4j-spring-security.version>0.7.0-SNAPSHOT</webauthn4j-spring-security.version>
  ...
</properties>

<dependency>
	<groupId>com.webauthn4j</groupId>
	<artifactId>webauthn4j-spring-security-core</artifactId>
	<version>${webauthn4j-spring-security.version}</version>
</dependency>
```

## Build

WebAuthn4J Spring Security uses a Gradle based build system.
In the instructions below, `gradlew` is invoked from the root of the source tree and serves as a cross-platform,
self-contained bootstrap mechanism for the build.

### Prerequisites

- Java8 or later
- Spring Framework 5.0 or later

### Checkout sources

```bash
git clone https://github.com/webauthn4j/webauthn4j-spring-security
```

### Build all jars

```bash
./gradlew build
```

### Execute sample application

```bash
./gradlew samples:spa:bootRun
```

![Login view](./docs/src/reference/asciidoc/en/images/login.png "Login view")

## Configuration

WebAuthn4J Spring Security can be configured through Spring Security Java Config.

```java
@Configuration
@EnableWebSecurity
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

    @Override
    public void configure(AuthenticationManagerBuilder builder) throws Exception {
        builder.apply(new WebAuthnAuthenticationProviderConfigurer<>(webAuthnAuthenticatorService, webAuthnManager));
        builder.userDetailsService(userDetailsService).passwordEncoder(passwordEncoder);
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {

        // WebAuthn Login
        http.apply(WebAuthnLoginConfigurer.webAuthnLogin())
                .defaultSuccessUrl("/", true)
                .rpId("example.com")
                .attestationOptionsEndpoint()
                    .rp()
                        .name("WebAuthn4J Spring Security Sample MPA")
                        .and()
                    .pubKeyCredParams(
                        new PublicKeyCredentialParameters(PublicKeyCredentialType.PUBLIC_KEY, COSEAlgorithmIdentifier.ES256),
                        new PublicKeyCredentialParameters(PublicKeyCredentialType.PUBLIC_KEY, COSEAlgorithmIdentifier.RS1)
                    )
                    .attestation(AttestationConveyancePreference.DIRECT)
                    .extensions()
                        .uvm(true)
                        .credProps(true);
    }
}
```


## License

WebAuthn4J Spring Security is Open Source software released under the
[Apache 2.0 license](http://www.apache.org/licenses/LICENSE-2.0.html).
