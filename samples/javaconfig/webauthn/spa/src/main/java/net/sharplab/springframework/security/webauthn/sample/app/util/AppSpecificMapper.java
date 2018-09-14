package net.sharplab.springframework.security.webauthn.sample.app.util;

import com.webauthn4j.util.Base64UrlUtil;
import net.sharplab.springframework.security.webauthn.sample.app.api.AuthenticatorForm;
import net.sharplab.springframework.security.webauthn.sample.app.api.ProfileCreateForm;
import net.sharplab.springframework.security.webauthn.sample.app.api.ProfileForm;
import net.sharplab.springframework.security.webauthn.sample.app.api.ProfileUpdateForm;
import net.sharplab.springframework.security.webauthn.sample.app.api.admin.UserCreateForm;
import net.sharplab.springframework.security.webauthn.sample.app.api.admin.UserForm;
import net.sharplab.springframework.security.webauthn.sample.app.api.admin.UserUpdateForm;
import net.sharplab.springframework.security.webauthn.sample.domain.exception.WebAuthnSampleEntityNotFoundException;
import net.sharplab.springframework.security.webauthn.sample.domain.model.Authenticator;
import net.sharplab.springframework.security.webauthn.sample.domain.model.User;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageImpl;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

@Component
public class AppSpecificMapper {

    @Autowired
    PasswordEncoder passwordEncoder;

    public User mapForCreate(UserCreateForm userForm){
        User user = new User();
        user.setId(null);
        user.setUserHandle(mapFromBase64Url(userForm.getUserHandle()));
        user.setFirstName(userForm.getFirstName());
        user.setLastName(userForm.getLastName());
        user.setEmailAddress(userForm.getEmailAddress());

        // authenticators
        if(userForm.getAuthenticators() == null){
            userForm.setAuthenticators(new ArrayList<>());
        }
        if(user.getAuthenticators() == null){
            user.setAuthenticators(new ArrayList<>());
        }
        mapToAuthenticatorListForCreate(userForm.getAuthenticators(), user.getAuthenticators());

        user.setSingleFactorAuthenticationAllowed(userForm.isSingleFactorAuthenticationAllowed());
        user.setLocked(userForm.isLocked());

        return user;
    }

    public User mapForUpdate(UserUpdateForm userForm, User user){
        user.setUserHandle(mapFromBase64Url(userForm.getUserHandle()));
        user.setFirstName(userForm.getFirstName());
        user.setLastName(userForm.getLastName());
        user.setEmailAddress(userForm.getEmailAddress());

        // authenticators
        if(userForm.getAuthenticators() == null){
            userForm.setAuthenticators(new ArrayList<>());
        }
        mapToAuthenticatorListForUpdate(userForm.getAuthenticators(), user.getAuthenticators());

        user.setSingleFactorAuthenticationAllowed(userForm.isSingleFactorAuthenticationAllowed());
        user.setLocked(userForm.isLocked());

        return user;
    }

    public UserForm mapToUserForm(User user) {
        UserForm userForm = new UserForm();
        userForm.setId(user.getId());
        userForm.setUserHandle(mapToBase64Url(user.getUserHandle()));
        userForm.setFirstName(user.getFirstName());
        userForm.setLastName(user.getLastName());
        userForm.setEmailAddress(user.getEmailAddress());

        // authenticators
        mapToAuthenticatorFormList(user.getAuthenticators(), userForm.getAuthenticators());
        userForm.setSingleFactorAuthenticationAllowed(user.isSingleFactorAuthenticationAllowed());
        userForm.setLocked(user.isLocked());

        return userForm;
    }

    public ProfileForm mapToProfileForm(User user) {
        ProfileForm profileForm = new ProfileForm();
        profileForm.setId(user.getId());
        profileForm.setUserHandle(mapToBase64Url(user.getUserHandle()));
        profileForm.setFirstName(user.getFirstName());
        profileForm.setLastName(user.getLastName());
        profileForm.setEmailAddress(user.getEmailAddress());

        // authenticators
        profileForm.setAuthenticators(new ArrayList<>());
        mapToAuthenticatorFormList(user.getAuthenticators(), profileForm.getAuthenticators());
        profileForm.setSingleFactorAuthenticationAllowed(user.isSingleFactorAuthenticationAllowed());

        return profileForm;
    }

    public Page<UserForm> mapToUserPage(Page<User> users) {
        return new PageImpl<>(users.stream().map(this::mapToUserForm).collect(Collectors.toList()), users.getPageable(), users.getTotalElements());
    }

    private Authenticator mapForCreate(AuthenticatorForm authenticatorForm){
        Authenticator authenticator = new Authenticator();
        authenticator.setName(authenticatorForm.getName());
        authenticator.setAttestationStatement(authenticatorForm.getAttestationObject().getAttestationObject().getAttestationStatement());
        authenticator.setAttestedCredentialData(authenticatorForm.getAttestationObject().getAttestationObject().getAuthenticatorData().getAttestedCredentialData());
        return authenticator;
    }

    private Authenticator mapForUpdate(AuthenticatorForm authenticatorForm, Authenticator authenticator){
        authenticator.setName(authenticatorForm.getName());
        // attestationStatement and attestedCredentialData won't be updated
        return authenticator;
    }

    private AuthenticatorForm mapToAuthenticatorForm(Authenticator authenticator) {
        AuthenticatorForm authenticatorForm = new AuthenticatorForm();
        authenticatorForm.setId(authenticator.getId());
        authenticatorForm.setCredentialId(Base64UrlUtil.encodeToString(authenticator.getAttestedCredentialData().getCredentialId()));
        authenticatorForm.setName(authenticator.getName());
        return authenticatorForm;
    }

    public User mapForCreate(ProfileCreateForm profileCreateForm) {
        User user = new User();
        user.setId(null);
        user.setUserHandle(mapFromBase64Url(profileCreateForm.getUserHandle()));
        user.setFirstName(profileCreateForm.getFirstName());
        user.setLastName(profileCreateForm.getLastName());
        user.setEmailAddress(profileCreateForm.getEmailAddress());
        user.setPassword(passwordEncoder.encode(profileCreateForm.getPassword()));

        // authenticators
        user.setAuthenticators(new ArrayList<>());
        mapToAuthenticatorListForCreate(profileCreateForm.getAuthenticators(), user.getAuthenticators());
        user.setSingleFactorAuthenticationAllowed(profileCreateForm.isSingleFactorAuthenticationAllowed());

        return user;
    }

    public User mapForUpdate(ProfileUpdateForm profileUpdateForm, User user){
        user.setUserHandle(mapFromBase64Url(profileUpdateForm.getUserHandle()));
        user.setFirstName(profileUpdateForm.getFirstName());
        user.setLastName(profileUpdateForm.getLastName());
        user.setEmailAddress(profileUpdateForm.getEmailAddress());

        // authenticators
        List<AuthenticatorForm> authenticatorForms = profileUpdateForm.getAuthenticators();
        mapToAuthenticatorListForUpdate(authenticatorForms, user.getAuthenticators());


        user.setSingleFactorAuthenticationAllowed(profileUpdateForm.isSingleFactorAuthenticationAllowed());

        return user;
    }

    private List<AuthenticatorForm> mapToAuthenticatorFormList(List<Authenticator> authenticators, List<AuthenticatorForm> authenticatorForms) {
        for(Authenticator authenticator: authenticators){
            authenticatorForms.add(mapToAuthenticatorForm(authenticator));
        }
        return authenticatorForms;
    }

    private List<Authenticator> mapToAuthenticatorListForCreate(List<AuthenticatorForm> authenticatorForms, List<Authenticator> authenticators) {
        for(AuthenticatorForm authenticatorForm: authenticatorForms){
            authenticators.add(mapForCreate(authenticatorForm));
        }
        return authenticators;
    }

    private List<Authenticator> mapToAuthenticatorListForUpdate(List<AuthenticatorForm> authenticatorForms, List<Authenticator> authenticators) {
        int[] sortedKeptIds = authenticatorForms.stream()
                .filter(authenticator -> authenticator.getId() != null)
                .mapToInt(AuthenticatorForm::getId).sorted().toArray();
        for(AuthenticatorForm authenticatorForm: authenticatorForms){
            Integer id = authenticatorForm.getId();
            // add new authenticator
            if(id == null){
                authenticators.add(mapForCreate(authenticatorForm));
            }
            // update existing authenticator
            else {
                Authenticator correspondingAuthenticator =
                        authenticators.stream().filter(item -> item.getId().equals(id))
                                .findFirst().orElseThrow(()-> new WebAuthnSampleEntityNotFoundException("Corresponding authenticator is not found."));
                mapForUpdate(authenticatorForm, correspondingAuthenticator);
            }

        }
        // delete authenticators if it is not included in authenticatorForms
        authenticators.removeIf(authenticator -> {
            Integer id = authenticator.getId();
            if(id == null){
                return false;
            }
            return Arrays.binarySearch(sortedKeptIds, id) < 0;
        });
        return authenticators;
    }

    public byte[] mapFromBase64Url(String base64url){
        return Base64UrlUtil.decode(base64url);
    }

    public String mapToBase64Url(byte[] bytes) {
        return Base64UrlUtil.encodeToString(bytes);
    }


}
