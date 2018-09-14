package net.sharplab.springframework.security.webauthn.sample.domain.model;

import org.springframework.security.core.GrantedAuthority;

import java.util.List;

/**
 * Authority model
 */
public class Authority implements GrantedAuthority {

    private int id;

    private List<User> users;
    private List<Group> groups;

    private String authority;

    public Authority() {
        //NOP
    }

    public Authority(int id) {
        this.id = id;
    }

    public Authority(String authority) {
        this.authority = authority;
    }

    public Authority(int id, String authority) {
        this.id = id;
        this.authority = authority;
    }

    public Authority(int id, String authority, List<User> users, List<Group> groups) {
        this.id = id;
        this.authority = authority;
        this.users = users;
        this.groups = groups;
    }

    public int getId() {
        return id;
    }

    public void setId(int id) {
        this.id = id;
    }

    public List<User> getUsers() {
        return users;
    }

    public void setUsers(List<User> users) {
        this.users = users;
    }

    public List<Group> getGroups() {
        return groups;
    }

    public void setGroups(List<Group> groups) {
        this.groups = groups;
    }

    @Override
    public String getAuthority() {
        return authority;
    }

    public void setAuthority(String authority) {
        this.authority = authority;
    }

    @Override
    public String toString() {
        return authority;
    }
}
