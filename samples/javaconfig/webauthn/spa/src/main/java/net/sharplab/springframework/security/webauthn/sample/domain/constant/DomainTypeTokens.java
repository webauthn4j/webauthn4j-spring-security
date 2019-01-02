package net.sharplab.springframework.security.webauthn.sample.domain.constant;

import net.sharplab.springframework.security.webauthn.sample.domain.entity.AuthorityEntity;
import net.sharplab.springframework.security.webauthn.sample.domain.entity.GroupEntity;
import net.sharplab.springframework.security.webauthn.sample.domain.entity.UserEntity;
import org.modelmapper.TypeToken;
import org.springframework.data.domain.PageImpl;

import java.lang.reflect.Type;
import java.util.ArrayList;

/**
 * ModelMapper TypeToken constants
 */
public class DomainTypeTokens {

    public static final Type UserEntityList = new TypeToken<ArrayList<net.sharplab.springframework.security.webauthn.sample.domain.entity.GroupEntity>>() {
    }.getType();
    public static final Type GroupEntityList = new TypeToken<ArrayList<net.sharplab.springframework.security.webauthn.sample.domain.entity.GroupEntity>>() {
    }.getType();
    public static final Type AuthorityEntityList = new TypeToken<ArrayList<net.sharplab.springframework.security.webauthn.sample.domain.entity.AuthorityEntity>>() {
    }.getType();
    public static final Type AuthenticatorEntityList = new TypeToken<ArrayList<net.sharplab.springframework.security.webauthn.sample.domain.entity.AuthenticatorEntity>>() {
    }.getType();

    public static final Type UserPage = new TypeToken<PageImpl<UserEntity>>() {
    }.getType();
    public static final Type GroupPage = new TypeToken<PageImpl<GroupEntity>>() {
    }.getType();
    public static final Type AuthorityPage = new TypeToken<PageImpl<AuthorityEntity>>() {
    }.getType();

    private DomainTypeTokens() {
    }
}
