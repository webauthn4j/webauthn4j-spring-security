package net.sharplab.springframework.security.webauthn.sample.domain.model;

import net.sharplab.springframework.security.webauthn.userdetails.WebAuthnUserDetails;

import java.util.List;

/**
 * ユーザーモデル
 */
public class User implements WebAuthnUserDetails {

    private Integer id;
    private byte[] userHandle;
    private String firstName;
    private String lastName;
    private String emailAddress;

    private List<Authority> authorities;

    private List<Group> groups;

    private String password;

    private List<Authenticator> authenticators;

    private boolean locked;

    private boolean singleFactorAuthenticationAllowed = false;

    public User() {
        //NOP
    }

    public User(int id) {
        this.id = id;
    }

    public User(Integer id, byte[] userHandle, String firstName, String lastName, String emailAddress, List<Authority> authorities, List<Group> groups, List<Authenticator> authenticators, boolean locked, boolean singleFactorAuthenticationAllowed) {
        this.id = id;
        this.userHandle = userHandle;
        this.firstName = firstName;
        this.lastName = lastName;
        this.emailAddress = emailAddress;
        this.authorities = authorities;
        this.groups = groups;
        this.authenticators = authenticators;
        this.locked = locked;
        this.singleFactorAuthenticationAllowed = singleFactorAuthenticationAllowed;
    }

    /**
     * 姓名を返却する
     *
     * @return 姓名
     */
    @SuppressWarnings("WeakerAccess")
    public String getFullname() {
        return firstName + " " + lastName;
    }

    /**
     * ユーザー名を返却する
     *
     * @return ユーザー名
     */
    @Override
    public String getUsername() {
        return getEmailAddress();
    }

    @Override
    public List<Authenticator> getAuthenticators() {
        return this.authenticators;
    }

    @Override
    public boolean isSingleFactorAuthenticationAllowed() {
        return this.singleFactorAuthenticationAllowed;
    }

    @Override
    public void setSingleFactorAuthenticationAllowed(boolean singleFactorAuthenticationAllowed) {
        this.singleFactorAuthenticationAllowed = singleFactorAuthenticationAllowed;
    }

    /**
     * アカウントが有効期限内か
     *
     * @return アカウントが有効期限内の場合<code>true</code>
     */
    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    /**
     * アカウントがロックされていないか
     *
     * @return アカウントがロックされていない場合<code>true</code>
     */
    @Override
    public boolean isAccountNonLocked() {
        return !locked;
    }

    /**
     * アカウントの認証情報が有効か
     *
     * @return アカウントの認証情報が有効の場合<code>true</code>
     */
    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    /**
     * アカウントが有効か
     *
     * @return アカウントが有効の場合<code>true</code>
     */
    @Override
    public boolean isEnabled() {
        return true;
    }

    public Integer getId() {
        return id;
    }

    public void setId(Integer id) {
        this.id = id;
    }

    public byte[] getUserHandle() {
        return userHandle;
    }

    public void setUserHandle(byte[] userHandle) {
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

    @Override
    public List<Authority> getAuthorities() {
        return authorities;
    }

    public void setAuthorities(List<Authority> authorities) {
        this.authorities = authorities;
    }

    public List<Group> getGroups() {
        return groups;
    }

    public void setGroups(List<Group> groups) {
        this.groups = groups;
    }

    @Override
    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public void setAuthenticators(List<Authenticator> authenticators) {
        this.authenticators = authenticators;
    }

    public boolean isLocked() {
        return locked;
    }

    public void setLocked(boolean locked) {
        this.locked = locked;
    }
}
