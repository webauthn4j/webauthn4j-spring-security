package net.sharplab.springframework.security.webauthn.sample.app.api.validator;

import net.sharplab.springframework.security.webauthn.sample.app.api.ProfileUpdateForm;
import org.springframework.stereotype.Component;
import org.springframework.validation.Errors;
import org.springframework.validation.Validator;

@Component
public class ProfileUpdateFormValidator implements Validator {

    @Override
    public boolean supports(Class<?> clazz) {
        return ProfileUpdateForm.class.isAssignableFrom(clazz);
    }

    @Override
    public void validate(Object target, Errors errors) {
        ProfileUpdateForm form = (ProfileUpdateForm) target;

        int authenticatorCount = 0;
        if(form.getAuthenticators() != null){
            authenticatorCount = form.getAuthenticators().size();
        }

        if(!form.isSingleFactorAuthenticationAllowed() && authenticatorCount == 0){
            errors.rejectValue("authenticators",
                    "e.ProfileCreateFormValidator.noAuthenticator",
                    "To disable password authentication, at least one authenticator must be registered.");
        }
    }
}
