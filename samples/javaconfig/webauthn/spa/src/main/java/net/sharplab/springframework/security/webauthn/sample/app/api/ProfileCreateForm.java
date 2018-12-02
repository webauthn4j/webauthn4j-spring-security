package net.sharplab.springframework.security.webauthn.sample.app.api;

import javax.servlet.http.HttpServletRequest;
import javax.validation.Valid;
import javax.validation.constraints.Email;
import javax.validation.constraints.NotEmpty;
import javax.validation.constraints.NotNull;
import java.util.List;

public class ProfileCreateForm {

    private HttpServletRequest request;

    @NotEmpty
    private String userHandle;

    @NotEmpty
    private String firstName;

    @NotEmpty
    private String lastName;

    @NotEmpty
    @Email
    private String emailAddress;

    @NotEmpty
    private String password;

    @Valid
    private List<AuthenticatorForm> authenticators;

    @NotNull
    private Boolean singleFactorAuthenticationAllowed;

    public HttpServletRequest getRequest() {
        return request;
    }

    public void setRequest(HttpServletRequest request) {
        this.request = request;
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

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public List<AuthenticatorForm> getAuthenticators() {
        return authenticators;
    }

    public void setAuthenticators(List<AuthenticatorForm> authenticators) {
        this.authenticators = authenticators;
    }

    public Boolean isSingleFactorAuthenticationAllowed() {
        return singleFactorAuthenticationAllowed;
    }

    public void setSingleFactorAuthenticationAllowed(Boolean singleFactorAuthenticationAllowed) {
        this.singleFactorAuthenticationAllowed = singleFactorAuthenticationAllowed;
    }
}
