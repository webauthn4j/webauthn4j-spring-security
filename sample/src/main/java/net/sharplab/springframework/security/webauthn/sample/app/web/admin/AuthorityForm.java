package net.sharplab.springframework.security.webauthn.sample.app.web.admin;

import java.util.List;

/**
 * Form for Authority
 */
public class AuthorityForm {

    private List<Integer> users;

    private List<Integer> groups;

    public List<Integer> getUsers() {
        return users;
    }

    public void setUsers(List<Integer> users) {
        this.users = users;
    }

    public List<Integer> getGroups() {
        return groups;
    }

    public void setGroups(List<Integer> groups) {
        this.groups = groups;
    }
}
