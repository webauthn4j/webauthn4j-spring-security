package net.sharplab.springframework.security.webauthn.sample.domain.component;

import net.sharplab.springframework.security.webauthn.sample.domain.constant.DomainTypeTokens;
import net.sharplab.springframework.security.webauthn.sample.domain.constant.MessageCodes;
import net.sharplab.springframework.security.webauthn.sample.domain.entity.AuthorityEntity;
import net.sharplab.springframework.security.webauthn.sample.domain.entity.GroupEntity;
import net.sharplab.springframework.security.webauthn.sample.domain.entity.UserEntity;
import net.sharplab.springframework.security.webauthn.sample.domain.exception.WebAuthnSampleEntityNotFoundException;
import net.sharplab.springframework.security.webauthn.sample.domain.repository.AuthorityEntityRepository;
import net.sharplab.springframework.security.webauthn.sample.domain.repository.GroupEntityRepository;
import net.sharplab.springframework.security.webauthn.sample.domain.repository.UserEntityRepository;
import org.modelmapper.ModelMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;
import org.terasoluna.gfw.common.message.ResultMessages;

import java.util.List;

/**
 * {@inheritDoc}
 */
@Component
@Transactional
public class GroupManagerImpl implements GroupManager {

    private final ModelMapper modelMapper;

    private final UserEntityRepository userEntityRepository;
    private final GroupEntityRepository groupEntityRepository;
    private final AuthorityEntityRepository authorityEntityRepository;

    @Autowired
    public GroupManagerImpl(ModelMapper mapper, UserEntityRepository userEntityRepository, GroupEntityRepository groupEntityRepository, AuthorityEntityRepository authorityEntityRepository) {
        this.modelMapper = mapper;
        this.userEntityRepository = userEntityRepository;
        this.groupEntityRepository = groupEntityRepository;
        this.authorityEntityRepository = authorityEntityRepository;
    }


    @Override
    public GroupEntity findGroup(int groupId) {
        return groupEntityRepository.findById(groupId)
                .orElseThrow(() -> new WebAuthnSampleEntityNotFoundException(ResultMessages.error().add(MessageCodes.Error.Group.GROUP_NOT_FOUND)));
    }

    @Override
    public List<GroupEntity> findAllGroups() {
        return groupEntityRepository.findAll();
    }

    @Override
    public List<UserEntity> findUsersInGroup(int groupId) {
        GroupEntity groupEntity = groupEntityRepository.findById(groupId)
                .orElseThrow(() -> new WebAuthnSampleEntityNotFoundException(ResultMessages.error().add(MessageCodes.Error.Group.GROUP_NOT_FOUND)));
        return groupEntity.getUsers();
    }

    @Override
    public List<UserEntity> findUsersInGroup(String groupName) {
        GroupEntity groupEntity = groupEntityRepository.findOneByGroupName(groupName)
                .orElseThrow(() -> new WebAuthnSampleEntityNotFoundException(ResultMessages.error().add(MessageCodes.Error.Group.GROUP_NOT_FOUND)));

        return groupEntity.getUsers();
    }

    @Override
    public GroupEntity createGroup(GroupEntity groupEntity) {
        return groupEntityRepository.save(groupEntity);
    }

    @Override
    public void deleteGroup(int groupId) {
        groupEntityRepository.deleteById(groupId);
    }

    @Override
    public void renameGroup(int groupId, String newName) {
        GroupEntity groupEntity = groupEntityRepository.findById(groupId)
                .orElseThrow(() -> new WebAuthnSampleEntityNotFoundException(ResultMessages.error().add(MessageCodes.Error.Group.GROUP_NOT_FOUND)));

        groupEntity.setGroupName(newName);
    }

    @Override
    public void addUserToGroup(int userId, int groupId) {
        UserEntity userEntityEntity = userEntityRepository.findById(userId)
                .orElseThrow(() -> new WebAuthnSampleEntityNotFoundException(ResultMessages.error().add(MessageCodes.Error.User.USER_NOT_FOUND)));

        GroupEntity groupEntity = groupEntityRepository.findById(groupId)
                .orElseThrow(() -> new WebAuthnSampleEntityNotFoundException(ResultMessages.error().add(MessageCodes.Error.Group.GROUP_NOT_FOUND)));

        groupEntity.getUsers().add(userEntityEntity);
    }

    @Override
    public void removeUserFromGroup(int userId, int groupId) {
        GroupEntity groupEntity = groupEntityRepository.findById(groupId)
                .orElseThrow(() -> new WebAuthnSampleEntityNotFoundException(ResultMessages.error().add(MessageCodes.Error.Group.GROUP_NOT_FOUND)));
        groupEntity.getUsers().remove(userId);
    }

    @Override
    public List<AuthorityEntity> findGroupAuthorities(int groupId) {
        GroupEntity groupEntity = groupEntityRepository.findById(groupId)
                .orElseThrow(() -> new WebAuthnSampleEntityNotFoundException(ResultMessages.error().add(MessageCodes.Error.Group.GROUP_NOT_FOUND)));
        return modelMapper.map(groupEntity.getAuthorities(), DomainTypeTokens.AuthorityEntityList);
    }

    @Override
    public void addGroupAuthority(int groupId, AuthorityEntity authority) {
        GroupEntity groupEntity = groupEntityRepository.findById(groupId)
                .orElseThrow(() -> new WebAuthnSampleEntityNotFoundException(ResultMessages.error().add(MessageCodes.Error.Group.GROUP_NOT_FOUND)));
        AuthorityEntity authorityEntityEntity = modelMapper.map(authority, AuthorityEntity.class);
        groupEntity.getAuthorities().add(authorityEntityEntity);
    }

    @Override
    public void removeGroupAuthority(int groupId, AuthorityEntity authority) {
        GroupEntity groupEntity = groupEntityRepository.findById(groupId)
                .orElseThrow(() -> new WebAuthnSampleEntityNotFoundException(ResultMessages.error().add(MessageCodes.Error.Group.GROUP_NOT_FOUND)));
        AuthorityEntity authorityEntityEntity = authorityEntityRepository.findById(authority.getId())
                .orElseThrow(() -> new WebAuthnSampleEntityNotFoundException(ResultMessages.error().add(MessageCodes.Error.Authority.AUTHORITY_NOT_FOUND)));

        groupEntity.getAuthorities().remove(authorityEntityEntity);
    }

}
