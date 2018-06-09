package net.sharplab.springframework.security.webauthn.sample.app.web.admin;

import net.sharplab.springframework.security.webauthn.sample.app.util.validator.EqualProperties;
import net.sharplab.springframework.security.webauthn.sample.app.web.AuthenticatorCreateForm;

import javax.validation.Valid;
import javax.validation.constraints.Email;
import javax.validation.constraints.NotEmpty;
import javax.validation.constraints.NotNull;
import java.util.List;

/**
 * Form for User
 */
@EqualProperties(property = "rawPassword", comparingProperty = "rawPasswordRetyped")
public class UserCreateForm {

    @NotNull //TODO
    private String userHandle;

    @NotEmpty
    private String firstName;

    @NotEmpty
    private String lastName;

    @NotEmpty
    @Email
    private String emailAddress;

    @NotEmpty
    private String rawPassword;

    @NotEmpty
    private String rawPasswordRetyped;

    @Valid
    private List<AuthenticatorCreateForm> newAuthenticators;

    @NotNull
    private Boolean passwordAuthenticationAllowed;

    @NotNull
    private Boolean locked;

    public String getUserHandle() {
        return userHandle;
    }

    public void setUserHandle(String userHandle) {
        this.userHandle = userHandle;
    }

    public String getFirstName() {
        return firstName;
    }

    public void setFirstName(String firstName) {
        this.firstName = firstName;
    }

    public String getLastName() {
        return lastName;
    }

    public void setLastName(String lastName) {
        this.lastName = lastName;
    }

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

    public List<AuthenticatorCreateForm> getNewAuthenticators() {
        return newAuthenticators;
    }

    public void setNewAuthenticators(List<AuthenticatorCreateForm> newAuthenticators) {
        this.newAuthenticators = newAuthenticators;
    }

    public Boolean getPasswordAuthenticationAllowed() {
        return passwordAuthenticationAllowed;
    }

    public void setPasswordAuthenticationAllowed(Boolean passwordAuthenticationAllowed) {
        this.passwordAuthenticationAllowed = passwordAuthenticationAllowed;
    }

    public Boolean getLocked() {
        return locked;
    }

    public void setLocked(Boolean locked) {
        this.locked = locked;
    }
}
