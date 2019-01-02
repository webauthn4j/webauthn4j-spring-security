package net.sharplab.springframework.security.webauthn.sample.domain.component;

import com.webauthn4j.authenticator.Authenticator;
import com.webauthn4j.util.Base64UrlUtil;
import net.sharplab.springframework.security.webauthn.exception.CredentialIdNotFoundException;
import net.sharplab.springframework.security.webauthn.sample.domain.entity.AuthenticatorEntity;
import net.sharplab.springframework.security.webauthn.sample.domain.entity.UserEntity;
import net.sharplab.springframework.security.webauthn.sample.domain.exception.WebAuthnSampleEntityNotFoundException;
import net.sharplab.springframework.security.webauthn.sample.domain.repository.AuthenticatorEntityRepository;
import net.sharplab.springframework.security.webauthn.sample.domain.repository.UserEntityRepository;
import org.modelmapper.ModelMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.Assert;

import java.util.Optional;

@Transactional
@Component
public class AuthenticatorManagerImpl implements AuthenticatorManager {

    private Logger logger = LoggerFactory.getLogger(AuthenticatorManagerImpl.class);

    private ModelMapper modelMapper;

    private UserEntityRepository userEntityRepository;
    private AuthenticatorEntityRepository authenticatorEntityRepository;

    public AuthenticatorManagerImpl(ModelMapper modelMapper, UserEntityRepository userEntityRepository, AuthenticatorEntityRepository authenticatorEntityRepository) {
        this.modelMapper = modelMapper;
        this.userEntityRepository = userEntityRepository;
        this.authenticatorEntityRepository = authenticatorEntityRepository;
    }

    @Override
    public void updateCounter(byte[] credentialId, long counter) throws CredentialIdNotFoundException {
        AuthenticatorEntity authenticatorEntity = authenticatorEntityRepository.findOneByCredentialId(credentialId)
                        .orElseThrow(()-> new CredentialIdNotFoundException("AuthenticatorEntity not found"));
        authenticatorEntity.setCounter(counter);
    }

    @Override
    public void createAuthenticator(Authenticator authenticator) {
        this.validateAuthenticator(authenticator);
        AuthenticatorEntity authenticatorEntity = modelMapper.map(authenticator, AuthenticatorEntity.class);
        authenticatorEntityRepository.save(authenticatorEntity);
    }

    @Override
    public void addAuthenticatorToUser(byte[] credentialId, String username)  {
        String credentialIdStr = Base64UrlUtil.encodeToString(credentialId);
        this.logger.debug("Adding authenticator '{}' to user '{}'", credentialIdStr, username);
        Assert.isTrue(credentialId.length > 0, "credentialId must not be empty");
        Assert.hasText(username, "username should have text");
        UserEntity userEntity = userEntityRepository.findOneByEmailAddress(username)
                .orElseThrow(()-> new UsernameNotFoundException("UserEntity not found"));
        AuthenticatorEntity authenticatorEntity = authenticatorEntityRepository.findOneByCredentialId(credentialId)
                .orElseThrow(()-> new CredentialIdNotFoundException("AuthenticatorEntity not found"));
        userEntity.getAuthenticators().add(authenticatorEntity);
    }

    private void validateAuthenticator(Authenticator authenticator) {
    }
}
