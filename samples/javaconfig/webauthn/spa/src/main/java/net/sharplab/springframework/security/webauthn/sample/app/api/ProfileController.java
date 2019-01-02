package net.sharplab.springframework.security.webauthn.sample.app.api;

import net.sharplab.springframework.security.webauthn.sample.app.api.validator.spring.ProfileCreateFormValidator;
import net.sharplab.springframework.security.webauthn.sample.app.api.validator.spring.ProfileUpdateFormValidator;
import net.sharplab.springframework.security.webauthn.sample.app.service.ProfileAppService;
import net.sharplab.springframework.security.webauthn.sample.app.util.AppSpecificMapper;
import net.sharplab.springframework.security.webauthn.sample.domain.entity.UserEntity;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.WebDataBinder;
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

    @InitBinder("profileCreateForm")
    public void initProfileCreateFormBinder(WebDataBinder binder) {
        binder.addValidators(profileCreateFormValidator);
    }

    @InitBinder("profileUpdateForm")
    public void initProfileUpdateFormBinder(WebDataBinder binder) {
        binder.addValidators(profileUpdateFormValidator);
    }

    @GetMapping
    public ProfileForm show(@AuthenticationPrincipal UserEntity loginUserEntity){
        UserEntity userEntity = profileAppService.findOne(loginUserEntity.getId());
        return mapper.mapToProfileForm(userEntity);
    }

    @PostMapping
    public ProfileForm create(@Valid @RequestBody ProfileCreateForm profileCreateForm){
        UserEntity userEntity = mapper.mapForCreate(profileCreateForm);
        UserEntity createdUserEntity = profileAppService.create(userEntity);
        return mapper.mapToProfileForm(createdUserEntity);
    }

    @PutMapping
    public ProfileForm update(@AuthenticationPrincipal UserEntity loginUserEntity, @Valid @RequestBody ProfileUpdateForm profileUpdateForm){
        int id = loginUserEntity.getId();
        UserEntity updatedUserEntity = profileAppService.update(id, profileUpdateForm);
        return mapper.mapToProfileForm(updatedUserEntity);
    }

    @DeleteMapping
    public void delete(@AuthenticationPrincipal UserEntity loginUserEntity){
        int id = loginUserEntity.getId();
        profileAppService.delete(id);
        SecurityContextHolder.clearContext();
    }

}
