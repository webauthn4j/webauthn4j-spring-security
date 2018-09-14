package net.sharplab.springframework.security.webauthn.sample.app.service;

import net.sharplab.springframework.security.webauthn.sample.app.api.admin.UserUpdateForm;
import net.sharplab.springframework.security.webauthn.sample.app.util.AppSpecificMapper;
import net.sharplab.springframework.security.webauthn.sample.domain.model.User;
import net.sharplab.springframework.security.webauthn.sample.domain.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

@Service
@Transactional
public class UserAppServiceImpl implements UserAppService {

    @Autowired
    private UserService userService;

    @Autowired
    private AppSpecificMapper mapper;

    @Transactional(readOnly = true)
    @Override
    public User findOne(int id) {
        return userService.findOne(id);
    }

    @Transactional(readOnly = true)
    @Override
    public List<User> findAll() {
        return userService.findAll();
    }

    @Transactional(readOnly = true)
    @Override
    public Page<User> findAll(Pageable pageable) {
        return userService.findAll(pageable);
    }

    @Transactional(readOnly = true)
    @Override
    public Page<User> findAllByKeyword(Pageable pageable, String keyword) {
        return userService.findAllByKeyword(pageable, keyword);
    }

    @Override
    public User create(User user) {
        return userService.create(user);
    }

    @Transactional
    @Override
    public User update(int id, UserUpdateForm userUpdateForm) {
        return userService.update(id, user -> mapper.mapForUpdate(userUpdateForm, user));
    }

    @Transactional
    @Override
    public void delete(int id) {
        delete(id);
    }
}
