package net.sharplab.springframework.security.webauthn.sample.app.api;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.webauthn4j.util.Base64UrlUtil;
import net.sharplab.springframework.security.webauthn.sample.app.api.admin.UserCreateForm;
import net.sharplab.springframework.security.webauthn.sample.app.api.admin.UserUpdateForm;
import net.sharplab.springframework.security.webauthn.sample.app.config.AppConfig;
import net.sharplab.springframework.security.webauthn.sample.app.config.TestSecurityConfig;
import net.sharplab.springframework.security.webauthn.sample.app.service.ProfileAppService;
import net.sharplab.springframework.security.webauthn.sample.app.test.WithMockUser;
import net.sharplab.springframework.security.webauthn.sample.domain.model.User;
import net.sharplab.springframework.security.webauthn.sample.infrastructure.config.InfrastructureMockConfig;
import net.sharplab.springframework.security.webauthn.sample.util.UUIDUtil;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.security.test.context.support.WithAnonymousUser;
import org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.servlet.MockMvc;

import java.util.Collections;
import java.util.UUID;

import static org.hamcrest.Matchers.empty;
import static org.hamcrest.Matchers.is;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@RunWith(SpringRunner.class)
@WebMvcTest(ProfileController.class)
@Import(value = {TestSecurityConfig.class, AppConfig.class, InfrastructureMockConfig.class})
public class ProfileControllerTest {

    @Autowired
    private MockMvc mvc;

    @MockBean
    ProfileAppService profileAppService;

    @Autowired
    ObjectMapper objectMapper;

    @Test
    @WithMockUser(id=1, firstName = "John", lastName = "Doe", emailAddress = "john.doe@example.com", authorities = {"ROLE_USER"}, authenticators = {})
    public void show_test() throws Exception{
        int userId = 1;

        User user = new User();
        user.setUserHandle(new byte[0]);
        user.setId(userId);
        user.setFirstName("John");
        user.setLastName("Doe");
        user.setEmailAddress("john.doe@example.com");
        user.setAuthenticators(Collections.emptyList());
        user.setSingleFactorAuthenticationAllowed(true);

        when(profileAppService.findOne(userId)).thenReturn(user);

        //When
        mvc.perform(get("/api/profile"))
        //Then
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.id", is(1)))
        .andExpect(jsonPath("$.userHandle", is("")))
        .andExpect(jsonPath("$.firstName", is("John")))
        .andExpect(jsonPath("$.lastName", is("Doe")))
        .andExpect(jsonPath("$.emailAddress", is("john.doe@example.com")))
        .andExpect(jsonPath("$.authenticators", is(empty())))
        .andExpect(jsonPath("$.singleFactorAuthenticationAllowed", is(true)))
        ;
    }

    @Test
    @WithAnonymousUser
    public void create_test() throws Exception{

        ProfileCreateForm userCreateForm = new ProfileCreateForm();
        userCreateForm.setUserHandle("ORZClsZpTvWrYGl7mXL5Wg");
        userCreateForm.setFirstName("John");
        userCreateForm.setLastName("Doe");
        userCreateForm.setEmailAddress("john.doe@example.com");
        userCreateForm.setPassword("password");
        userCreateForm.setAuthenticators(Collections.emptyList());
        userCreateForm.setSingleFactorAuthenticationAllowed(true);

        User user = new User();
        user.setId(1);
        user.setUserHandle(Base64UrlUtil.decode("ORZClsZpTvWrYGl7mXL5Wg"));
        user.setFirstName("John");
        user.setLastName("Doe");
        user.setEmailAddress("john.doe@example.com");
        user.setAuthenticators(Collections.emptyList());
        user.setSingleFactorAuthenticationAllowed(true);

        when(profileAppService.create(any())).thenReturn(user);

        //When
        mvc.perform(
                post("/api/profile")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(userCreateForm))
                .with(SecurityMockMvcRequestPostProcessors.csrf())
        )
        //Then
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.id", is(1)))
        .andExpect(jsonPath("$.userHandle", is("ORZClsZpTvWrYGl7mXL5Wg")))
        .andExpect(jsonPath("$.firstName", is("John")))
        .andExpect(jsonPath("$.lastName", is("Doe")))
        .andExpect(jsonPath("$.emailAddress", is("john.doe@example.com")))
        .andExpect(jsonPath("$.authenticators", is(empty())))
        .andExpect(jsonPath("$.singleFactorAuthenticationAllowed", is(true)))
        ;
        verify(profileAppService).create(any());
    }

    @Test
    @WithMockUser(id=1, firstName = "John", lastName = "Doe", emailAddress = "john.doe@example.com", authorities = {"ROLE_USER"}, authenticators = {})
    public void update_test() throws Exception{
        int userId = 1;

        ProfileUpdateForm userUpdateForm = new ProfileUpdateForm();
        userUpdateForm.setUserHandle("");
        userUpdateForm.setFirstName("John");
        userUpdateForm.setLastName("Smith");
        userUpdateForm.setEmailAddress("john.smith@example.com");
        userUpdateForm.setAuthenticators(Collections.emptyList());
        userUpdateForm.setSingleFactorAuthenticationAllowed(true);

        byte[] userHandle = UUIDUtil.toByteArray(UUID.randomUUID());

        User user = new User();
        user.setId(userId);
        user.setUserHandle(userHandle);
        user.setId(userId);
        user.setFirstName("John");
        user.setLastName("Smith");
        user.setEmailAddress("john.smith@example.com");
        user.setAuthenticators(Collections.emptyList());
        user.setSingleFactorAuthenticationAllowed(true);

        when(profileAppService.update(anyInt(), any())).thenReturn(user);

        //When
        mvc.perform(
                put("/api/profile")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(user))
                        .with(SecurityMockMvcRequestPostProcessors.csrf())
        )
        //Then
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.id", is(1)))
        .andExpect(jsonPath("$.userHandle", is(Base64UrlUtil.encodeToString(userHandle))))
        .andExpect(jsonPath("$.firstName", is("John")))
        .andExpect(jsonPath("$.lastName", is("Smith")))
        .andExpect(jsonPath("$.emailAddress", is("john.smith@example.com")))
        .andExpect(jsonPath("$.authenticators", is(empty())))
        .andExpect(jsonPath("$.singleFactorAuthenticationAllowed", is(true)))
        ;
        verify(profileAppService).update(anyInt(), any());
    }

    @Test
    @WithMockUser(id=1, firstName = "John", lastName = "Doe", emailAddress = "john.doe@example.com", authorities = {"ROLE_USER"}, authenticators = {})
    public void delete_test() throws Exception{

        //When
        mvc.perform(
                delete("/api/profile")
                .with(SecurityMockMvcRequestPostProcessors.csrf())
        )
        //Then
        .andExpect(status().isOk());
        verify(profileAppService).delete(anyInt());
    }

}
