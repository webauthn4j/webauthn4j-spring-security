package net.sharplab.springframework.security.webauthn.config.configurers;

import com.webauthn4j.validator.WebAuthnAuthenticationContextValidator;
import net.sharplab.springframework.security.webauthn.WebAuthnAuthenticationProvider;
import net.sharplab.springframework.security.webauthn.challenge.ChallengeRepository;
import net.sharplab.springframework.security.webauthn.challenge.HttpSessionChallengeRepository;
import net.sharplab.springframework.security.webauthn.server.ServerPropertyProvider;
import net.sharplab.springframework.security.webauthn.server.ServerPropertyProviderImpl;
import net.sharplab.springframework.security.webauthn.userdetails.WebAuthnUserDetailsService;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.context.annotation.Bean;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.test.context.junit4.SpringRunner;

import static net.sharplab.springframework.security.webauthn.config.configurers.WebAuthnLoginConfigurer.webAuthnLogin;
import static org.assertj.core.api.Assertions.assertThat;

@RunWith(SpringRunner.class)
public class WebAuthnAuthenticationProviderConfigurerSpringTest {

    @Autowired
    ProviderManager providerManager;

    @Test
    public void test() {
        assertThat(providerManager.getProviders()).extracting("class").contains(WebAuthnAuthenticationProvider.class);
    }

    @EnableWebSecurity
    static class Config extends WebSecurityConfigurerAdapter {

        @MockBean
        private WebAuthnUserDetailsService userDetailsService;

        @Bean
        public ChallengeRepository challengeRepository() {
            return new HttpSessionChallengeRepository();
        }

        @Bean
        public ServerPropertyProvider serverPropertyProvider(ChallengeRepository challengeRepository) {
            ServerPropertyProviderImpl serverPropertyProvider = new ServerPropertyProviderImpl(challengeRepository);
            serverPropertyProvider.setRpId("example.com");
            return serverPropertyProvider;
        }

        @Bean
        @Override
        public AuthenticationManager authenticationManagerBean() throws Exception {
            return super.authenticationManager();
        }

        @Override
        protected void configure(HttpSecurity http) throws Exception {

            // Authentication
            http.apply(webAuthnLogin());

            // Authorization
            http.authorizeRequests()
                    .antMatchers("/login").permitAll()
                    .anyRequest().authenticated();
        }

        @Override
        public void configure(AuthenticationManagerBuilder builder) throws Exception {
            builder.apply(new WebAuthnAuthenticationProviderConfigurer<>(userDetailsService))
                    .authenticationContextValidator(new WebAuthnAuthenticationContextValidator());
        }

    }

}
