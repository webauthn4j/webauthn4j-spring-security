package net.sharplab.springframework.security.webauthn.sample.app.api.validator;

import com.webauthn4j.validator.exception.ValidationException;
import net.sharplab.springframework.security.webauthn.WebAuthnRegistrationRequestValidator;
import net.sharplab.springframework.security.webauthn.sample.app.api.AuthenticatorForm;
import org.springframework.stereotype.Component;
import org.springframework.validation.Errors;

import javax.servlet.http.HttpServletRequest;

@Component
public class AuthenticatorFormValidator {

    private WebAuthnRegistrationRequestValidator webAuthnRegistrationRequestValidator;

    public AuthenticatorFormValidator(WebAuthnRegistrationRequestValidator webAuthnRegistrationRequestValidator) {
        this.webAuthnRegistrationRequestValidator = webAuthnRegistrationRequestValidator;
    }

    public void validate(HttpServletRequest request, AuthenticatorForm form, Errors errors) {
        if(form.getId() == null){
            if(form.getAttestationObject() == null){
                errors.rejectValue("attestationObject", "not.null");
            }
            if(form.getClientData() == null){
                errors.rejectValue("clientData", "not.null");
            }
            if(form.getClientExtensionsJSON() == null){
                errors.rejectValue("clientExtensionsJSON", "not.null");
            }
            try{
                webAuthnRegistrationRequestValidator.validate(
                        request,
                        form.getClientData().getClientDataBase64(),
                        form.getAttestationObject().getAttestationObjectBase64(),
                        form.getClientExtensionsJSON());
            }
            catch (ValidationException exception){
                errors.reject("e.AuthenticatorFormValidator.invalidAuthenticator", "Authenticator is invalid.");
            }

        }
    }
}
