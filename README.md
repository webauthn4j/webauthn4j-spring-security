# WebAuthn4J Spring Security

[![Actions Status](https://github.com/webauthn4j/webauthn4j-spring-security/workflows/CI/badge.svg)](https://github.com/webauthn4j/webauthn4j-spring-security/actions)
[![Coverage](https://sonarcloud.io/api/project_badges/measure?project=webauthn4j-spring-security&metric=coverage)](https://sonarcloud.io/dashboard?id=webauthn4j-spring-security)
[![Maven Central](https://img.shields.io/maven-central/v/com.webauthn4j/webauthn4j-spring-security-core.svg)](https://search.maven.org/search?q=webauthn4j-spring-security)
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
  <webauthn4j-spring-security.version>0.12.0.RELEASE</webauthn4j-spring-security.version>
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

- Java17 or later
- Spring Framework 6.0 or later

### Checkout sources

```bash
git clone https://github.com/webauthn4j/webauthn4j-spring-security
```

### Build all jars

```bash
./gradlew build
```

## sample applications

Sample applications are available in [webauthn4j-spring-security-samples](https://github.com/webauthn4j/webauthn4j-spring-security-samples)

```bash
./gradlew samples:spa:bootRun
```

![Login view](./docs/src/reference/asciidoc/en/images/login.png "Login view")

## Configuration

WebAuthn4J Spring Security can be configured through Spring Security Java Config.

```java
@Configuration
@EnableWebSecurity
public class WebSecurityConfig {

    @Bean
    public WebAuthnAuthenticationProvider webAuthnAuthenticationProvider(WebAuthnCredentialRecordService webAuthnCredentialRecordService, WebAuthnManager webAuthnManager){
        return new WebAuthnAuthenticationProvider(webAuthnCredentialRecordService, webAuthnManager);
    }

    @Bean
    public DaoAuthenticationProvider daoAuthenticationProvider(UserDetailsService userDetailsService){
        DaoAuthenticationProvider daoAuthenticationProvider = new DaoAuthenticationProvider();
        daoAuthenticationProvider.setUserDetailsService(userDetailsService);
        daoAuthenticationProvider.setPasswordEncoder(new BCryptPasswordEncoder());
        return daoAuthenticationProvider;
    }

    @Bean
    public AuthenticationManager authenticationManager(List<AuthenticationProvider> providers){
        return new ProviderManager(providers);
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http, AuthenticationManager authenticationManager) throws Exception {
        // WebAuthn Login
        http.apply(WebAuthnLoginConfigurer.webAuthnLogin())
                .loginPage("/login")
                .usernameParameter("username")
                .passwordParameter("rawPassword")
                .credentialIdParameter("credentialId")
                .clientDataJSONParameter("clientDataJSON")
                .authenticatorDataParameter("authenticatorData")
                .signatureParameter("signature")
                .clientExtensionsJSONParameter("clientExtensionsJSON")
                .loginProcessingUrl("/login")
                .rpId("example.com")
                .attestationOptionsEndpoint()
                .attestationOptionsProvider(attestationOptionsProvider)
                .processingUrl("/webauthn/attestation/options")
                .rp()
                .name("example")
                .and()
                .pubKeyCredParams(
                        new PublicKeyCredentialParameters(PublicKeyCredentialType.PUBLIC_KEY, COSEAlgorithmIdentifier.ES256),
                        new PublicKeyCredentialParameters(PublicKeyCredentialType.PUBLIC_KEY, COSEAlgorithmIdentifier.RS1)
                )
                .authenticatorSelection()
                .authenticatorAttachment(AuthenticatorAttachment.CROSS_PLATFORM)
                .residentKey(ResidentKeyRequirement.PREFERRED)
                .userVerification(UserVerificationRequirement.PREFERRED)
                .and()
                .attestation(AttestationConveyancePreference.DIRECT)
                .extensions()
                .credProps(true)
                .uvm(true)
                .and()
                .assertionOptionsEndpoint()
                .assertionOptionsProvider(assertionOptionsProvider)
                .processingUrl("/webauthn/assertion/options")
                .rpId("example.com")
                .userVerification(UserVerificationRequirement.PREFERRED)
                .and()
                .authenticationManager(authenticationManager);
    }
}
```


## License

WebAuthn4J Spring Security is Open Source software released under the
[Apache 2.0 license](http://www.apache.org/licenses/LICENSE-2.0.html).
