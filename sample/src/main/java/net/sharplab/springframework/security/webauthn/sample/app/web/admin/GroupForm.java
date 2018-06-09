package net.sharplab.springframework.security.webauthn.sample.app.web.admin;

import javax.validation.constraints.NotEmpty;

/**
 * form for Group
 */
public class GroupForm {

    @NotEmpty
    private String groupName;

    public String getGroupName() {
        return groupName;
    }

    public void setGroupName(String groupName) {
        this.groupName = groupName;
    }
}
