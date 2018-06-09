package net.sharplab.springframework.security.webauthn.sample.app.web.admin;

import net.sharplab.springframework.security.webauthn.sample.app.util.validator.EqualProperties;

import javax.validation.constraints.NotEmpty;

/**
 * Form for User password
 */
@EqualProperties(property = "rawPassword", comparingProperty = "rawPasswordRetyped")
public class UserPasswordForm {

    private String emailAddress;

    @NotEmpty
    private String rawPassword;

    @NotEmpty
    private String rawPasswordRetyped;

    public String getEmailAddress() {
        return emailAddress;
    }

    public void setEmailAddress(String emailAddress) {
        this.emailAddress = emailAddress;
    }

    public String getRawPassword() {
        return rawPassword;
    }

    public void setRawPassword(String rawPassword) {
        this.rawPassword = rawPassword;
    }

    public String getRawPasswordRetyped() {
        return rawPasswordRetyped;
    }

    public void setRawPasswordRetyped(String rawPasswordRetyped) {
        this.rawPasswordRetyped = rawPasswordRetyped;
    }
}
