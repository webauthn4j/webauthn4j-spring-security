package net.sharplab.springframework.security.webauthn.sample.domain.model;

import java.io.Serializable;
import java.util.List;

/**
 * Group model
 */
public class Group implements Serializable {

    private Integer id;
    private String groupName;

    private List<User> users;
    private List<Authority> authorities;

    public Group() {
        //NOP
    }

    public Group(String group) {
        groupName = group;
    }

    public Group(int id) {
        this.id = id;
    }

    public Integer getId() {
        return id;
    }

    public void setId(Integer id) {
        this.id = id;
    }

    public String getGroupName() {
        return groupName;
    }

    public void setGroupName(String groupName) {
        this.groupName = groupName;
    }

    public List<User> getUsers() {
        return users;
    }

    public void setUsers(List<User> users) {
        this.users = users;
    }

    public List<Authority> getAuthorities() {
        return authorities;
    }

    public void setAuthorities(List<Authority> authorities) {
        this.authorities = authorities;
    }
}
