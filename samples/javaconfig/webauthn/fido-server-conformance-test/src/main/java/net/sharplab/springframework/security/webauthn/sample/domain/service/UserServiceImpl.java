package net.sharplab.springframework.security.webauthn.sample.domain.service;

import net.sharplab.springframework.security.webauthn.sample.domain.component.UserManager;
import net.sharplab.springframework.security.webauthn.sample.domain.entity.UserEntity;
import net.sharplab.springframework.security.webauthn.sample.domain.repository.UserEntityRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.function.Consumer;

/**
 * ユーザーサービス
 */
@Service
@Transactional
public class UserServiceImpl implements UserService {

    private final UserEntityRepository userEntityRepository;
    private final UserManager userManager;

    @Autowired
    public UserServiceImpl(UserEntityRepository userEntityRepository, UserManager userManager) {
        this.userEntityRepository = userEntityRepository;
        this.userManager = userManager;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public UserEntity findOne(int id) {
        return userManager.findById(id);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public List<UserEntity> findAll() {
        return userEntityRepository.findAll();
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public Page<UserEntity> findAll(Pageable pageable) {
        return userEntityRepository.findAll(pageable);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public Page<UserEntity> findAllByKeyword(Pageable pageable, String keyword) {
        if (keyword == null) {
            return userEntityRepository.findAll(pageable);
        } else {
            return userEntityRepository.findAllByKeyword(pageable, keyword);
        }
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public UserEntity create(UserEntity userEntity) {
        return userManager.createUser(userEntity);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public UserEntity update(int id, Consumer<UserEntity> consumer) {
        UserEntity userEntity = findOne(id);
        consumer.accept(userEntity);
        userManager.updateUser(userEntity);
        return userEntity;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void delete(int id) {
        userManager.deleteUser(id);
    }
}
