package net.sharplab.springframework.security.webauthn.sample.app.api.validator.spring;

import com.webauthn4j.validator.exception.ValidationException;
import net.sharplab.springframework.security.webauthn.sample.app.api.AuthenticatorForm;
import net.sharplab.springframework.security.webauthn.sample.app.api.ProfileUpdateForm;
import net.sharplab.springframework.security.webauthn.sample.app.api.validator.AuthenticatorFormValidator;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.springframework.validation.Errors;
import org.springframework.validation.Validator;

import javax.servlet.http.HttpServletRequest;

@Component
public class ProfileUpdateFormValidator implements Validator {

    @Autowired
    private HttpServletRequest request;

    private AuthenticatorFormValidator authenticatorFormValidator;

    public ProfileUpdateFormValidator(AuthenticatorFormValidator authenticatorFormValidator) {
        this.authenticatorFormValidator = authenticatorFormValidator;
    }

    @Override
    public boolean supports(Class<?> clazz) {
        return ProfileUpdateForm.class.isAssignableFrom(clazz);
    }

    @Override
    public void validate(Object target, Errors errors) {
        ProfileUpdateForm form = (ProfileUpdateForm) target;

        if(form.getAuthenticators() == null || form.getAuthenticators().isEmpty()) {

            if (!form.isSingleFactorAuthenticationAllowed()) {
                errors.rejectValue("authenticators",
                        "e.ProfileUpdateFormValidator.noAuthenticator",
                        "To disable password authentication, at least one authenticator must be registered.");
            }
        }
        else{
            for(AuthenticatorForm authenticator : form.getAuthenticators()){
                try{
                    authenticatorFormValidator.validate(request, authenticator, errors);
                }
                catch (ValidationException exception){
                    errors.rejectValue("authenticators", "e.ProfileUpdateFormValidator.invalidAuthenticator", "Authenticator is invalid.");
                }
            }
        }
    }
}
