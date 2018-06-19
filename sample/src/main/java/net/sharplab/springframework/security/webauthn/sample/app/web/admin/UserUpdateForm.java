package net.sharplab.springframework.security.webauthn.sample.app.web.admin;

import net.sharplab.springframework.security.webauthn.sample.app.web.AuthenticatorCreateForm;
import net.sharplab.springframework.security.webauthn.sample.app.web.AuthenticatorUpdateForm;

import javax.validation.Valid;
import javax.validation.constraints.Email;
import javax.validation.constraints.NotEmpty;
import javax.validation.constraints.NotNull;
import java.util.List;

/**
 * Form for User Update
 */
public class UserUpdateForm {

    private String userHandle;

    @NotEmpty
    private String firstName;

    @NotEmpty
    private String lastName;

    @NotEmpty
    @Email
    private String emailAddress;

    private boolean requireResidentKey;

    @Valid
    private List<AuthenticatorUpdateForm> authenticators;

    @Valid
    private List<AuthenticatorCreateForm> newAuthenticators;

    private boolean passwordAuthenticationAllowed;

    private boolean locked;

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

    public boolean isRequireResidentKey() {
        return requireResidentKey;
    }

    public void setRequireResidentKey(boolean requireResidentKey) {
        this.requireResidentKey = requireResidentKey;
    }

    public List<AuthenticatorUpdateForm> getAuthenticators() {
        return authenticators;
    }

    public void setAuthenticators(List<AuthenticatorUpdateForm> authenticators) {
        this.authenticators = authenticators;
    }

    public List<AuthenticatorCreateForm> getNewAuthenticators() {
        return newAuthenticators;
    }

    public void setNewAuthenticators(List<AuthenticatorCreateForm> newAuthenticators) {
        this.newAuthenticators = newAuthenticators;
    }

    public boolean isPasswordAuthenticationAllowed() {
        return passwordAuthenticationAllowed;
    }

    public void setPasswordAuthenticationAllowed(boolean passwordAuthenticationAllowed) {
        this.passwordAuthenticationAllowed = passwordAuthenticationAllowed;
    }

    public boolean isLocked() {
        return locked;
    }

    public void setLocked(boolean locked) {
        this.locked = locked;
    }
}
