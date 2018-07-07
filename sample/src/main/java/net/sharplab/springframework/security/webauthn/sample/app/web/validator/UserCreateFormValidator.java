package net.sharplab.springframework.security.webauthn.sample.app.web.validator;

import net.sharplab.springframework.security.webauthn.sample.app.web.admin.UserCreateForm;
import org.springframework.stereotype.Component;
import org.springframework.validation.Errors;
import org.springframework.validation.Validator;

@Component
public class UserCreateFormValidator implements Validator {
    @Override
    public boolean supports(Class<?> clazz) {
        return UserCreateForm.class.isAssignableFrom(clazz);
    }

    @Override
    public void validate(Object target, Errors errors) {
        UserCreateForm form = (UserCreateForm) target;

        int authenticatorCount = 0;
        if(form.getNewAuthenticators() != null){
            authenticatorCount += form.getNewAuthenticators().stream().filter(item -> !item.getDelete()).count();
        }

        if(!form.isSingleFactorAuthenticationAllowed() && authenticatorCount == 0){
            errors.rejectValue("newAuthenticators",
                    "e.UserCreateFormValidator.noAuthenticator",
                    "To disable password authentication, at least one authenticator must be registered.");
        }
    }
}
