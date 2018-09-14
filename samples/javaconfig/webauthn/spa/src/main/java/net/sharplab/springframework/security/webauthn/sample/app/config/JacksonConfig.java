package net.sharplab.springframework.security.webauthn.sample.app.config;

import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;

@Configuration
@ComponentScan(basePackages = "net.sharplab.springframework.security.webauthn.sample.app.util.jackson")
public class JacksonConfig {
}
