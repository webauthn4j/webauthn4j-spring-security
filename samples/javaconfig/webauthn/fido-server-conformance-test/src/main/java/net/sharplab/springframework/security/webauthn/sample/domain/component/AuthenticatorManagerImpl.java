package net.sharplab.springframework.security.webauthn.sample.domain.component;

import net.sharplab.springframework.security.webauthn.exception.CredentialIdNotFoundException;
import net.sharplab.springframework.security.webauthn.sample.domain.entity.AuthenticatorEntity;
import net.sharplab.springframework.security.webauthn.sample.domain.repository.AuthenticatorEntityRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

@Transactional
@Component
public class AuthenticatorManagerImpl implements AuthenticatorManager {

    private Logger logger = LoggerFactory.getLogger(AuthenticatorManagerImpl.class);

    private AuthenticatorEntityRepository authenticatorEntityRepository;

    public AuthenticatorManagerImpl(AuthenticatorEntityRepository authenticatorEntityRepository) {
        this.authenticatorEntityRepository = authenticatorEntityRepository;
    }

    @Override
    public void updateCounter(byte[] credentialId, long counter) throws CredentialIdNotFoundException {
        AuthenticatorEntity authenticatorEntity = authenticatorEntityRepository.findOneByCredentialId(credentialId)
                        .orElseThrow(()-> new CredentialIdNotFoundException("AuthenticatorEntity not found"));
        authenticatorEntity.setCounter(counter);
    }

}
