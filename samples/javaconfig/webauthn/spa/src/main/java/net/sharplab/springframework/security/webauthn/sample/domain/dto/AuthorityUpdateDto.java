package net.sharplab.springframework.security.webauthn.sample.domain.dto;

import java.io.Serializable;
import java.util.List;

/**
 * AuthorityUpdateDto
 */
public class AuthorityUpdateDto implements Serializable {

    private int id;

    private List<Integer> users;
    private List<Integer> groups;

    public int getId() {
        return id;
    }

    public void setId(int id) {
        this.id = id;
    }

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
