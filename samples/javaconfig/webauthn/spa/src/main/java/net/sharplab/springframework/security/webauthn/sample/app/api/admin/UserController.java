package net.sharplab.springframework.security.webauthn.sample.app.api.admin;

import net.sharplab.springframework.security.webauthn.sample.app.util.AppSpecificMapper;
import net.sharplab.springframework.security.webauthn.sample.domain.model.User;
import net.sharplab.springframework.security.webauthn.sample.domain.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

import javax.validation.Valid;

@RestController
@RequestMapping("/api/admin/user")
public class UserController {

    private final UserService userService;

    private final AppSpecificMapper mapper;

    @Autowired
    public UserController(UserService userService, AppSpecificMapper mapper) {
        this.userService = userService;
        this.mapper = mapper;
    }

    @GetMapping("/")
    public Page<UserForm> list(Pageable pageable, Model model, @RequestParam(required = false, value = "keyword") String keyword){
        Page<User> users = userService.findAllByKeyword(pageable, keyword);
        return mapper.mapToUserPage(users);
    }

    @GetMapping("/{id}")
    public UserForm show(@PathVariable(value = "id") int id){
        User user = userService.findOne(id);
        return mapper.mapToUserForm(user);
    }

    @PostMapping
    public UserForm create(@Valid @RequestBody UserCreateForm userCreateForm){
        User user = mapper.mapForCreate(userCreateForm);
        User createdUser = userService.create(user);
        return mapper.mapToUserForm(createdUser);
    }

    @PutMapping("/{id}")
    public UserForm update(@PathVariable(value = "id") int id, @Valid @RequestBody UserUpdateForm userUpdateForm){
        User updatedUser = userService.update(id, user -> mapper.mapForUpdate(userUpdateForm, user));
        return mapper.mapToUserForm(updatedUser);
    }

    @DeleteMapping("/{id}")
    public void delete(@PathVariable(value = "id") int id){
        userService.delete(id);
    }
}
