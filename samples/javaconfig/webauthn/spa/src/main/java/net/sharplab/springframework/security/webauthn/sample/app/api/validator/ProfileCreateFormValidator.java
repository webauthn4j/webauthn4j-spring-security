package net.sharplab.springframework.security.webauthn.sample.app.api.validator;

import com.webauthn4j.validator.exception.ValidationException;
import net.sharplab.springframework.security.webauthn.WebAuthnRegistrationRequestValidator;
import net.sharplab.springframework.security.webauthn.sample.app.api.AuthenticatorForm;
import net.sharplab.springframework.security.webauthn.sample.app.api.ProfileCreateForm;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.springframework.validation.Errors;
import org.springframework.validation.Validator;

@Component
public class ProfileCreateFormValidator implements Validator {

    private WebAuthnRegistrationRequestValidator webAuthnRegistrationRequestValidator;

    public ProfileCreateFormValidator(WebAuthnRegistrationRequestValidator webAuthnRegistrationRequestValidator) {
        this.webAuthnRegistrationRequestValidator = webAuthnRegistrationRequestValidator;
    }

    @Override
    public boolean supports(Class<?> clazz) {
        return ProfileCreateForm.class.isAssignableFrom(clazz);
    }

    @Override
    public void validate(Object target, Errors errors) {
        ProfileCreateForm form = (ProfileCreateForm) target;

        if(form.getAuthenticators() == null || form.getAuthenticators().isEmpty()) {

            if (!form.isSingleFactorAuthenticationAllowed()) {
                errors.rejectValue("authenticators",
                        "e.ProfileCreateFormValidator.noAuthenticator",
                        "To disable password authentication, at least one authenticator must be registered.");
            }
        }
        else{
            for(AuthenticatorForm authenticator : form.getAuthenticators()){
                try{
                    webAuthnRegistrationRequestValidator.validate(
                            form.getRequest(),
                            authenticator.getClientData().getClientDataBase64(),
                            authenticator.getAttestationObject().getAttestationObjectBase64(),
                            authenticator.getClientExtensionJSON());
                }
                catch (ValidationException exception){
                    errors.rejectValue("authenticators", "e.ProfileCreateFormValidator.invalidAuthenticator", "Authenticator is invalid.");
                }
            }

        }
    }
}
