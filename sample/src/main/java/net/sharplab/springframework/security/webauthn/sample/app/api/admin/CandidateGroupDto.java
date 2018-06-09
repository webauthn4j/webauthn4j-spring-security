package net.sharplab.springframework.security.webauthn.sample.app.api.admin;

/**
 * Candidate Group Dto
 */
public class CandidateGroupDto {
    private int id;
    private String groupName;

    public int getId() {
        return id;
    }

    public void setId(int id) {
        this.id = id;
    }

    public String getGroupName() {
        return groupName;
    }

    public void setGroupName(String groupName) {
        this.groupName = groupName;
    }
}
