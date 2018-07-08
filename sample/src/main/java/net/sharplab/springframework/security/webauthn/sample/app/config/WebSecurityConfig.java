package net.sharplab.springframework.security.webauthn.sample.app.config;

import net.sharplab.springframework.security.webauthn.authenticator.WebAuthnAuthenticatorService;
import net.sharplab.springframework.security.webauthn.config.configurers.WebAuthnAuthenticationConfigurer;
import net.sharplab.springframework.security.webauthn.userdetails.WebAuthnUserDetailsService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.security.authentication.MultiFactorAuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.authentication.configurers.mfa.MultiFactorAuthenticationProviderConfigurer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import javax.inject.Named;

import static net.sharplab.springframework.security.webauthn.config.configurers.WebAuthnLoginConfigurer.webAuthnLogin;


/**
 * Security Configuration
 */
@Configuration
@Import(value = WebSecurityBeanConfig.class)
@EnableWebSecurity
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

    private static final String ADMIN_ROLE = "ADMIN";

    @Autowired
    @Named("accessDeniedHandler")
    private AccessDeniedHandler accessDeniedHandler;

    @Autowired
    private DaoAuthenticationProvider daoAuthenticationProvider;

    @Autowired
    private WebAuthnUserDetailsService userDetailsService;

    @Autowired
    private WebAuthnAuthenticatorService authenticatorService;

    @Override
    public void configure(AuthenticationManagerBuilder builder) throws Exception {
        builder.apply(new WebAuthnAuthenticationConfigurer<>(userDetailsService, authenticatorService));
        builder.apply(new MultiFactorAuthenticationProviderConfigurer<>(daoAuthenticationProvider));
    }

    @Override
    public void configure(WebSecurity web) {
        // ignore static resources
        web.ignoring().antMatchers(
                "/image/**",
                "/css/**",
                "/js/**");
    }

    /**
     * Configure SecurityFilterChain
     */
    @Override
    protected void configure(HttpSecurity http) throws Exception {

        // WebAuthn Login
        http.apply(webAuthnLogin())
                .loginPage("/login")
                .usernameParameter("username")
                .passwordParameter("rawPassword");

        // Logout
        http.logout()
                .logoutRequestMatcher(new AntPathRequestMatcher("/logout**"))
                .logoutSuccessUrl("/login?logout=true");

        // Authorization
        http.authorizeRequests()
                .mvcMatchers("/login").permitAll()
                .mvcMatchers("/signup").permitAll()
                .mvcMatchers("/health/**").permitAll()
                .mvcMatchers("/info/**").permitAll()
                .mvcMatchers("/h2-console/**").denyAll()
                .mvcMatchers("/admin/**").hasRole(ADMIN_ROLE)
                .mvcMatchers("/api/admin/**").hasRole(ADMIN_ROLE)
                .anyRequest().fullyAuthenticated();

        http.exceptionHandling();

        http.sessionManagement()
                .invalidSessionUrl("/login?expired")
                .sessionAuthenticationErrorUrl("/login?expired");

        http.exceptionHandling().accessDeniedHandler(accessDeniedHandler);


    }

}
