package net.sharplab.springframework.security.webauthn.sample.app.api;

import org.springframework.validation.Errors;
import org.springframework.validation.Validator;

public class AuthenticatorFormValidator implements Validator {
    @Override
    public boolean supports(Class<?> clazz) {
        return AuthenticatorForm.class.isAssignableFrom(clazz);
    }

    @Override
    public void validate(Object target, Errors errors) {
        AuthenticatorForm form = (AuthenticatorForm) target;
        if(form.getId() == null){
            if(form.getAttestationObject() == null){
                errors.rejectValue("attestationObject", "not.null");
            }
            if(form.getClientData() == null){
                errors.rejectValue("collectedClientData", "not.null");
            }
        }
    }
}
