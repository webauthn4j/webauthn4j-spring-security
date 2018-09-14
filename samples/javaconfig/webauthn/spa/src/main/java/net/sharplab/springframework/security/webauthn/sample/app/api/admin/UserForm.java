package net.sharplab.springframework.security.webauthn.sample.app.api.admin;

import net.sharplab.springframework.security.webauthn.sample.app.api.AuthenticatorForm;

import java.util.List;

public class UserForm {

    private int id;

    private String userHandle;

    private String firstName;

    private String lastName;

    private String emailAddress;

    private List<AuthenticatorForm> authenticators;

    private boolean singleFactorAuthenticationAllowed;

    private boolean locked;

    public int getId() {
        return id;
    }

    public void setId(int id) {
        this.id = id;
    }

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

    public List<AuthenticatorForm> getAuthenticators() {
        return authenticators;
    }

    public void setAuthenticators(List<AuthenticatorForm> authenticators) {
        this.authenticators = authenticators;
    }

    public boolean isSingleFactorAuthenticationAllowed() {
        return singleFactorAuthenticationAllowed;
    }

    public void setSingleFactorAuthenticationAllowed(boolean singleFactorAuthenticationAllowed) {
        this.singleFactorAuthenticationAllowed = singleFactorAuthenticationAllowed;
    }

    public boolean isLocked() {
        return locked;
    }

    public void setLocked(boolean locked) {
        this.locked = locked;
    }
}
