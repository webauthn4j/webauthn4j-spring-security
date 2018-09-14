package net.sharplab.springframework.security.webauthn.sample.app.api;

import net.sharplab.springframework.security.webauthn.sample.app.api.validator.ProfileCreateFormValidator;
import net.sharplab.springframework.security.webauthn.sample.app.api.validator.ProfileUpdateFormValidator;
import net.sharplab.springframework.security.webauthn.sample.app.service.ProfileAppService;
import net.sharplab.springframework.security.webauthn.sample.app.util.AppSpecificMapper;
import net.sharplab.springframework.security.webauthn.sample.domain.model.User;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;

import javax.validation.Valid;

@RestController
@RequestMapping("/api/profile")
public class ProfileController {

    private final ProfileAppService profileAppService;

    private final AppSpecificMapper mapper;

    @Autowired
    private ProfileCreateFormValidator profileCreateFormValidator;

    @Autowired
    private ProfileUpdateFormValidator profileUpdateFormValidator;

    @Autowired
    public ProfileController(ProfileAppService profileAppService, AppSpecificMapper mapper) {
        this.profileAppService = profileAppService;
        this.mapper = mapper;
    }

    @GetMapping
    public ProfileForm show(@AuthenticationPrincipal User loginUser){
        User user = profileAppService.findOne(loginUser.getId());
        return mapper.mapToProfileForm(user);
    }

    @PostMapping
    public ProfileForm create(@Valid @RequestBody ProfileCreateForm profileCreateForm){
        User user = mapper.mapForCreate(profileCreateForm);
        User createdUser = profileAppService.create(user);
        return mapper.mapToProfileForm(createdUser);
    }

    @PutMapping
    public ProfileForm update(@AuthenticationPrincipal User loginUser, @Valid @RequestBody ProfileUpdateForm profileUpdateForm){
        int id = loginUser.getId();
        User updatedUser = profileAppService.update(id, profileUpdateForm);
        return mapper.mapToProfileForm(updatedUser);
    }

    @DeleteMapping
    public void delete(@AuthenticationPrincipal User loginUser){
        int id = loginUser.getId();
        profileAppService.delete(id);
        SecurityContextHolder.clearContext();
    }

}
