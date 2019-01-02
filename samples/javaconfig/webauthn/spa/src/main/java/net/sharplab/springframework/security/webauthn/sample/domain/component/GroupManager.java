package net.sharplab.springframework.security.webauthn.sample.domain.component;


import net.sharplab.springframework.security.webauthn.sample.domain.entity.AuthorityEntity;
import net.sharplab.springframework.security.webauthn.sample.domain.entity.GroupEntity;
import net.sharplab.springframework.security.webauthn.sample.domain.entity.UserEntity;

import java.util.List;

/**
 * GroupEntity manager
 */
@SuppressWarnings("WeakerAccess")
public interface GroupManager {

    /**
     * Locates a group
     *
     * @param groupId the group to locate
     * @return the group
     */
    GroupEntity findGroup(int groupId);

    /**
     * Returns all groups that this group manager controls.
     *
     * @return all groups
     */
    List<GroupEntity> findAllGroups();


    /**
     * Locates users who are members of a group
     *
     * @param groupId the group whose members are required
     * @return the users of the group members
     */
    List<UserEntity> findUsersInGroup(int groupId);

    /**
     * Locates the users who are members of a group
     *
     * @param groupName the group whose members are required
     * @return the users of the group
     */
    List<UserEntity> findUsersInGroup(String groupName);

    /**
     * Creates a new groupEntity with the specified list of authorityEntities.
     *
     * @param groupEntity the name for the new groupEntity
     * @return the created groupEntity
     */
    GroupEntity createGroup(GroupEntity groupEntity);

    /**
     * Removes a group, including all members and authorityEntities.
     *
     * @param groupId the group to remove.
     */
    void deleteGroup(int groupId);

    /**
     * Changes the name of a group without altering the assigned authorityEntities or members.
     *
     * @param groupId the group to rename.
     * @param newName new name
     */
    void renameGroup(int groupId, String newName);

    /**
     * Makes a user a member of a particular group.
     *
     * @param userId  the user to be given membership.
     * @param groupId the name of the group to which the user will be added.
     */
    void addUserToGroup(int userId, int groupId);

    /**
     * Deletes a user's membership of a group.
     *
     * @param userId  the user
     * @param groupId the group to remove the user from
     */
    void removeUserFromGroup(int userId, int groupId);

    /**
     * Obtains the list of authorityEntities which are assigned to a group.
     *
     * @param groupId the group
     * @return the list of authority the group owns
     */
    List<AuthorityEntity> findGroupAuthorities(int groupId);

    /**
     * Assigns a new authorityEntity to a group.
     *
     * @param groupId   the group to assign a new authorityEntity
     * @param authorityEntity the authorityEntity to be assigned
     */
    void addGroupAuthority(int groupId, AuthorityEntity authorityEntity);

    /**
     * Deletes an authorityEntity from those assigned to a group
     *
     * @param groupId   the group
     * @param authorityEntity the authorityEntity to be removed
     */
    void removeGroupAuthority(int groupId, AuthorityEntity authorityEntity);
}
