package net.sharplab.springframework.security.webauthn.sample.app.api.admin;

/**
 * Candidate User Dto
 */
public class CandidateUserDto {
    private int id;
    private String fullname;

    public int getId() {
        return id;
    }

    public void setId(int id) {
        this.id = id;
    }

    public String getFullname() {
        return fullname;
    }

    public void setFullname(String fullname) {
        this.fullname = fullname;
    }
}
