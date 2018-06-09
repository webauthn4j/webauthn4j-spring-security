package net.sharplab.springframework.security.webauthn.sample.app.web;

import javax.validation.constraints.NotEmpty;
import javax.validation.constraints.NotNull;

public class AuthenticatorUpdateForm {

    @NotNull
    private Integer id;

    @NotNull
    @NotEmpty
    private String name;

    @NotNull
    private Boolean delete;

    public Integer getId() {
        return id;
    }

    public void setId(Integer id) {
        this.id = id;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public Boolean getDelete() {
        return delete;
    }

    public void setDelete(Boolean delete) {
        this.delete = delete;
    }
}
