package net.sharplab.springframework.security.webauthn.sample.app.web;

import net.sharplab.springframework.security.webauthn.sample.app.util.validator.EqualProperties;

import javax.validation.constraints.NotEmpty;

/**
 * Form for profile password update
 */
@EqualProperties(property = "rawPassword", comparingProperty = "rawPasswordRetyped")
public class ProfilePasswordForm {

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
