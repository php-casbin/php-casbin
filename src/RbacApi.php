<?php

namespace Casbin;

/**
 * Trait RbacApi.
 *
 * @author techlee@qq.com
 */
trait RbacApi
{
    use RbacApiWithDomains;

    /**
     * gets the roles that a user has.
     *
     * @param string $name
     *
     * @return array
     */
    public function getRolesForUser($name)
    {
        return $this->model->model['g']['g']->rM->getRoles($name);
    }

    /**
     * gets the users that has a role.
     *
     * @param string $name
     *
     * @return array
     */
    public function getUsersForRole($name)
    {
        return $this->model->model['g']['g']->rM->getUsers($name);
    }

    /**
     * determines whether a user has a role.
     *
     * @param string $name
     * @param string $role
     *
     * @return bool
     */
    public function hasRoleForUser($name, $role)
    {
        $roles = $this->getRolesForUser($name);

        return in_array($role, $roles, true);
    }

    /**
     * adds a role for a user.
     * returns false if the user already has the role (aka not affected).
     *
     * @param string $user
     * @param string $role
     *
     * @return bool
     */
    public function addRoleForUser($user, $role)
    {
        return $this->addGroupingPolicy($user, $role);
    }

    /**
     * deletes a role for a user.
     * returns false if the user does not have the role (aka not affected).
     *
     * @param string $user
     * @param string $role
     *
     * @return bool
     */
    public function deleteRoleForUser($user, $role)
    {
        return $this->removeGroupingPolicy($user, $role);
    }

    /**
     * deletes all roles for a user.
     * returns false if the user does not have any roles (aka not affected).
     *
     * @param string $user
     *
     * @return bool
     */
    public function deleteRolesForUser($user)
    {
        return $this->removeFilteredGroupingPolicy(0, $user);
    }

    /**
     * deletes a user.
     * returns false if the user does not exist (aka not affected).
     *
     * @param string $user
     *
     * @return bool
     */
    public function deleteUser($user)
    {
        return $this->removeFilteredGroupingPolicy(0, $user);
    }

    /**
     * deletes a role.
     *
     * @param string $role
     */
    public function deleteRole($role)
    {
        $this->removeFilteredGroupingPolicy(1, $role);
        $this->removeFilteredPolicy(0, $role);
    }

    /**
     * deletes a permission.
     * returns false if the permission does not exist (aka not affected).
     *
     * @param string ...$permission
     *
     * @return bool
     */
    public function deletePermission(...$permission)
    {
        return $this->removeFilteredPolicy(1, ...$permission);
    }

    /**
     * adds a permission for a user or role.
     * returns false if the user or role already has the permission (aka not affected).
     *
     * @param string $user
     * @param string ...$permission
     *
     * @return bool
     */
    public function addPermissionForUser($user, ...$permission)
    {
        $params = array_merge([$user], $permission);

        return $this->addPolicy(...$params);
    }

    /**
     * deletes a permission for a user or role.
     * returns false if the user or role does not have the permission (aka not affected).
     *
     * @param string $user
     * @param string ...$permission
     *
     * @return bool
     */
    public function deletePermissionForUser($user, ...$permission)
    {
        $params = array_merge([$user], $permission);

        return $this->removePolicy(...$params);
    }

    /**
     * deletes permissions for a user or role.
     * returns false if the user or role does not have any permissions (aka not affected).
     *
     * @param string $user
     *
     * @return bool
     */
    public function deletePermissionsForUser($user)
    {
        return $this->removeFilteredPolicy(0, $user);
    }

    /**
     * gets permissions for a user or role.
     *
     * @param string $user
     *
     * @return array
     */
    public function getPermissionsForUser($user)
    {
        return $this->getFilteredPolicy(0, $user);
    }

    /**
     * determines whether a user has a permission.
     *
     * @param string $user
     * @param string ...$permission
     *
     * @return bool
     */
    public function hasPermissionForUser($user, ...$permission)
    {
        $params = array_merge([$user], $permission);

        return $this->hasPolicy($params);
    }

    /**
     * gets implicit roles that a user has.
     * Compared to getRolesForUser(), this function retrieves indirect roles besides direct roles.
     * For example:
     * g, alice, role:admin
     * g, role:admin, role:user.
     *
     * getRolesForUser("alice") can only get: ["role:admin"].
     * But getImplicitRolesForUser("alice") will get: ["role:admin", "role:user"].
     *
     * @param string $name
     * @param string $domain
     *
     * @return array
     */
    public function getImplicitRolesForUser($name, $domain = '')
    {
        $res = [];
        $roleSet = [];
        $roleSet[$name] = true;

        $q = [];
        $q[] = $name;

        for (; count($q) > 0;) {
            $name = $q[0];
            $q = array_slice($q, 1);

            $roles = $this->rm->getRoles($name, $domain);
            foreach ($roles as $r) {
                if (!isset($roleSet[$r])) {
                    $res[] = $r;
                    $q[] = $r;
                    $roleSet[$r] = true;
                }
            }
        }

        return $res;
    }

    /**
     * gets implicit permissions for a user or role.
     * Compared to getPermissionsForUser(), this function retrieves permissions for inherited roles.
     * For example:
     * p, admin, data1, read
     * p, alice, data2, read
     * g, alice, admin.
     *
     * getPermissionsForUser("alice") can only get: [["alice", "data2", "read"]].
     * But getImplicitPermissionsForUser("alice") will get: [["admin", "data1", "read"], ["alice", "data2", "read"]].
     *
     * @param string $user
     * @param string $domain
     *
     * @return array
     */
    public function getImplicitPermissionsForUser($user, $domain = '')
    {
        $roles[] = $user;
        $roles = array_merge(
            $roles,
            $this->getImplicitRolesForUser($user, $domain)
        );

        $res = [];
        foreach ($roles as $role) {
            if ('' != $domain) {
                $permissions = $this->getPermissionsForUserInDomain($role, $domain);
            } else {
                $permissions = $this->getPermissionsForUser($role);
            }

            $res = array_merge($res, $permissions);
        }

        return $res;
    }

    /**
     * gets implicit users for a permission.
     * For example:
     * p, admin, data1, read
     * p, bob, data1, read
     * g, alice, admin
     * getImplicitUsersForPermission("data1", "read") will get: ["alice", "bob"].
     * Note: only users will be returned, roles (2nd arg in "g") will be excluded.
     *
     * @param string ...$permission
     *
     * @return array
     */
    public function getImplicitUsersForPermission(...$permission)
    {
        $subjects = $this->getAllSubjects();
        $roles = $this->getAllRoles();

        $users = array_diff($subjects, $roles);

        $res = [];
        foreach ($users as $user) {
            $req = $permission;
            array_unshift($req, $user);
            $allowed = $this->enforce(...$req);

            if ($allowed) {
                $res[] = $user;
            }
        }

        return $res;
    }
}
