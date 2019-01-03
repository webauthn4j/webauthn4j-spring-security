package net.sharplab.springframework.security.webauthn.config.configurers;

import com.webauthn4j.registry.Registry;
import net.sharplab.springframework.security.webauthn.WebAuthnRegistrationRequestValidator;
import net.sharplab.springframework.security.webauthn.challenge.ChallengeRepository;
import net.sharplab.springframework.security.webauthn.challenge.HttpSessionChallengeRepository;
import net.sharplab.springframework.security.webauthn.endpoint.OptionsProvider;
import net.sharplab.springframework.security.webauthn.endpoint.OptionsProviderImpl;
import net.sharplab.springframework.security.webauthn.server.ServerPropertyProvider;
import net.sharplab.springframework.security.webauthn.server.ServerPropertyProviderImpl;
import net.sharplab.springframework.security.webauthn.userdetails.WebAuthnUserDetailsService;
import org.springframework.context.ApplicationContext;
import org.springframework.security.config.annotation.web.HttpSecurityBuilder;

class WebAuthnConfigurerUtil {

    private WebAuthnConfigurerUtil(){}

    static <H extends HttpSecurityBuilder<H>> ChallengeRepository getChallengeRepository(H http) {
        ApplicationContext applicationContext = http.getSharedObject(ApplicationContext.class);
        ChallengeRepository challengeRepository;
        String[] beanNames = applicationContext.getBeanNamesForType(ChallengeRepository.class);
        if (beanNames.length == 0) {
            challengeRepository = new HttpSessionChallengeRepository();
        } else {
            challengeRepository = applicationContext.getBean(ChallengeRepository.class);
        }
        return challengeRepository;
    }

    static <H extends HttpSecurityBuilder<H>> OptionsProvider getOptionsProvider(H http) {
        ApplicationContext applicationContext = http.getSharedObject(ApplicationContext.class);
        OptionsProvider optionsProvider;
        String[] beanNames = applicationContext.getBeanNamesForType(OptionsProvider.class);
        if (beanNames.length == 0) {
            WebAuthnUserDetailsService userDetailsService = applicationContext.getBean(WebAuthnUserDetailsService.class);
            optionsProvider = new OptionsProviderImpl(userDetailsService, getChallengeRepository(http));
        } else {
            optionsProvider = applicationContext.getBean(OptionsProvider.class);
        }
        return optionsProvider;
    }

    static <H extends HttpSecurityBuilder<H>> Registry getRegistry(H http){
        ApplicationContext applicationContext = http.getSharedObject(ApplicationContext.class);
        Registry registry;
        String[] beanNames = applicationContext.getBeanNamesForType(Registry.class);
        if (beanNames.length == 0) {
            registry = new Registry();
        } else {
            registry = applicationContext.getBean(Registry.class);
        }
        return registry;
    }

    static <H extends HttpSecurityBuilder<H>> ServerPropertyProvider getServerPropertyProvider(H http){
        ApplicationContext applicationContext = http.getSharedObject(ApplicationContext.class);
        ServerPropertyProvider serverPropertyProvider;
        String[] beanNames = applicationContext.getBeanNamesForType(ServerPropertyProvider.class);
        if (beanNames.length == 0) {
            serverPropertyProvider = new ServerPropertyProviderImpl(getOptionsProvider(http), getChallengeRepository(http));
        } else {
            serverPropertyProvider = applicationContext.getBean(ServerPropertyProvider.class);
        }
        return serverPropertyProvider;
    }

    static <H extends HttpSecurityBuilder<H>> WebAuthnUserDetailsService getWebAuthnUserDetailsService(H http) {
        ApplicationContext applicationContext = http.getSharedObject(ApplicationContext.class);
        return applicationContext.getBean(WebAuthnUserDetailsService.class);
    }

    static <H extends HttpSecurityBuilder<H>> WebAuthnRegistrationRequestValidator getWebAuthnRegistrationRequestValidator(H http) {
        ApplicationContext applicationContext = http.getSharedObject(ApplicationContext.class);
        return applicationContext.getBean(WebAuthnRegistrationRequestValidator.class);
    }
}
