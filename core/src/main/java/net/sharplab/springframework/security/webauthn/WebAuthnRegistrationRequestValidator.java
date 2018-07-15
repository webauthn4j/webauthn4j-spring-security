package net.sharplab.springframework.security.webauthn;

import com.webauthn4j.WebAuthnRegistrationContext;
import com.webauthn4j.server.ServerProperty;
import com.webauthn4j.util.Base64UrlUtil;
import com.webauthn4j.validator.WebAuthnRegistrationContextValidator;
import net.sharplab.springframework.security.webauthn.server.ServerPropertyProvider;

import javax.servlet.http.HttpServletRequest;
import java.util.List;


public class WebAuthnRegistrationRequestValidator {

    //~ Instance fields
    // ================================================================================================
    private WebAuthnRegistrationContextValidator registrationContextValidator;
    private ServerPropertyProvider serverPropertyProvider;

    private boolean userVerificationRequired;
    private List<String> expectedRegistrationExtensionIds;

    /**
     * Constructor
     *
     * @param registrationContextValidator validator for {@link WebAuthnRegistrationContext}
     * @param serverPropertyProvider       provider for {@link ServerProperty}
     */
    public WebAuthnRegistrationRequestValidator(WebAuthnRegistrationContextValidator registrationContextValidator, ServerPropertyProvider serverPropertyProvider) {
        this.registrationContextValidator = registrationContextValidator;
        this.serverPropertyProvider = serverPropertyProvider;
    }

    public void validate(HttpServletRequest httpServletRequest,
                         String clientDataBase64,
                         String attestationObjectBase64,
                         String clientExtensionsJSON
    ) {
        WebAuthnRegistrationContext registrationContext = createRegistrationContext(httpServletRequest, clientDataBase64, attestationObjectBase64, clientExtensionsJSON);
        registrationContextValidator.validate(registrationContext);
    }

    WebAuthnRegistrationContext createRegistrationContext(HttpServletRequest request,
                                                          String clientDataBase64,
                                                          String attestationObjectBase64,
                                                          String clientExtensionsJSON) {

        byte[] clientDataBytes = Base64UrlUtil.decode(clientDataBase64);
        byte[] attestationObjectBytes = Base64UrlUtil.decode(attestationObjectBase64);
        ServerProperty serverProperty = serverPropertyProvider.provide(request);

        return new WebAuthnRegistrationContext(
                clientDataBytes,
                attestationObjectBytes,
                clientExtensionsJSON,
                serverProperty,
                userVerificationRequired,
                expectedRegistrationExtensionIds);
    }

    /**
     * Check if user verification is required
     *
     * @return true if user verification is required
     */
    public boolean isUserVerificationRequired() {
        return userVerificationRequired;
    }

    /**
     * Set whether user verification is required
     *
     * @param userVerificationRequired true if user verification is required
     */
    public void setUserVerificationRequired(boolean userVerificationRequired) {
        this.userVerificationRequired = userVerificationRequired;
    }

    public List<String> getExpectedRegistrationExtensionIds() {
        return expectedRegistrationExtensionIds;
    }

    public void setExpectedRegistrationExtensionIds(List<String> expectedRegistrationExtensionIds) {
        this.expectedRegistrationExtensionIds = expectedRegistrationExtensionIds;
    }
}
