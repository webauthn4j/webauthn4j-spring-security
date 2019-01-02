package net.sharplab.springframework.security.webauthn.sample.app.service;

import net.sharplab.springframework.security.webauthn.sample.app.api.ProfileUpdateForm;
import net.sharplab.springframework.security.webauthn.sample.app.util.AppSpecificMapper;
import net.sharplab.springframework.security.webauthn.sample.domain.entity.UserEntity;
import net.sharplab.springframework.security.webauthn.sample.domain.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@Transactional
public class ProfileAppServiceImpl implements ProfileAppService {

    private final UserService userService;

    private final AppSpecificMapper mapper;

    @Autowired
    public ProfileAppServiceImpl(UserService userService, AppSpecificMapper mapper) {
        this.userService = userService;
        this.mapper = mapper;
    }

    @Override
    public UserEntity findOne(int id) {
        return userService.findOne(id);
    }

    @Override
    public UserEntity create(UserEntity userEntity) {
        return userService.create(userEntity);
    }

    @Override
    public UserEntity update(int id, ProfileUpdateForm profileUpdateForm) {
        return userService.update(id, user -> mapper.mapForUpdate(profileUpdateForm, user));
    }

    @Override
    public void delete(int id) {
        userService.delete(id);
    }
}
