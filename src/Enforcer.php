<?php

declare(strict_types=1);

namespace Casbin;

use Casbin\Exceptions\CasbinException;
use Casbin\Util\Util;

/**
 * Enforcer = ManagementEnforcer + RBAC API.
 *
 * @author techlee@qq.com
 */
class Enforcer extends ManagementEnforcer
{
    /**
     * Gets the roles that a user has.
     *
     * @param string $name
     * @param string ...$domain
     * @return string[]
     */
    public function getRolesForUser(string $name, string ...$domain): array
    {
        return $this->model['g']['g']->rm->getRoles($name, ...$domain);
    }

    /**
     * Gets the users that has a role.
     *
     * @param string $name
     * @param string ...$domain
     *
     * @return string[]
     */
    public function getUsersForRole(string $name, string ...$domain): array
    {
        return $this->model['g']['g']->rm->getUsers($name, ...$domain);
    }

    /**
     * Determines whether a user has a role.
     *
     * @param string $name
     * @param string $role
     * @param string ...$domain
     *
     * @return bool
     */
    public function hasRoleForUser(string $name, string $role, string ...$domain): bool
    {
        $roles = $this->getRolesForUser($name, ...$domain);

        return in_array($role, $roles, true);
    }

    /**
     * Adds a role for a user.
     * returns false if the user already has the role (aka not affected).
     *
     * @param string $user
     * @param string $role
     * @param string ...$domain
     * @return bool
     */
    public function addRoleForUser(string $user, string $role, string ...$domain): bool
    {
        return $this->addGroupingPolicy(...array_merge([$user, $role], $domain));
    }

    /**
     * @param string $user
     * @param string[] $roles
     * @param string ...$domain
     *
     * @return bool
     */
    public function addRolesForUser(string $user, array $roles, string ...$domain): bool
    {
        return $this->addGroupingPolicies(
            array_map(function ($role) use ($user, $domain) {
                return array_merge([$user, $role], $domain);
            }, $roles)
        );
    }

    /**
     * Deletes a role for a user.
     * returns false if the user does not have the role (aka not affected).
     *
     * @param string $user
     * @param string $role
     * @param string ...$domain
     *
     * @return bool
     */
    public function deleteRoleForUser(string $user, string $role, string ...$domain): bool
    {
        return $this->removeGroupingPolicy(...array_merge([$user, $role], $domain));
    }

    /**
     * Deletes all roles for a user.
     * Returns false if the user does not have any roles (aka not affected).
     *
     * @param string $user
     * @param string ...$domain
     *
     * @return bool
     * @throws CasbinException
     */
    public function deleteRolesForUser(string $user, string ...$domain): bool
    {
        if (count($domain) > 1) {
            throw new CasbinException('error: domain should be 1 parameter');
        }

        return $this->removeFilteredGroupingPolicy(0, ...array_merge([$user, ''], $domain));
    }

    /**
     * Deletes a user.
     * Returns false if the user does not exist (aka not affected).
     *
     * @param string $user
     *
     * @return bool
     */
    public function deleteUser(string $user): bool
    {
        $res1 = $this->removeFilteredGroupingPolicy(0, $user);
        $res2 = $this->removeFilteredPolicy(0, $user);

        return $res1 || $res2;
    }

    /**
     * Deletes a role.
     *
     * @param string $role
     * @return bool
     */
    public function deleteRole(string $role): bool
    {
        $res1 = $this->removeFilteredGroupingPolicy(1, $role);
        $res2 = $this->removeFilteredPolicy(0, $role);

        return $res1 || $res2;
    }

    /**
     * Deletes a permission.
     * Returns false if the permission does not exist (aka not affected).
     *
     * @param string ...$permission
     *
     * @return bool
     */
    public function deletePermission(string ...$permission): bool
    {
        return $this->removeFilteredPolicy(1, ...$permission);
    }

    /**
     * Adds a permission for a user or role.
     * Returns false if the user or role already has the permission (aka not affected).
     *
     * @param string $user
     * @param string ...$permission
     *
     * @return bool
     */
    public function addPermissionForUser(string $user, string ...$permission): bool
    {
        $params = array_merge([$user], $permission);

        return $this->addPolicy(...$params);
    }

    /**
     * AddPermissionsForUser adds multiple permissions for a user or role.
     * Returns false if the user or role already has one of the permissions (aka not affected).
     *
     * @param string $user
     * @param array  ...$permissions
     * @return bool
     */
    public function addPermissionsForUser(string $user, array ...$permissions): bool
    {
        $rules = [];
        foreach ($permissions as $permission) {
            $rules[] = array_merge([$user], $permission);
        }
        return $this->addPolicies($rules);
    }

    /**
     * Deletes a permission for a user or role.
     * Returns false if the user or role does not have the permission (aka not affected).
     *
     * @param string $user
     * @param string ...$permission
     *
     * @return bool
     */
    public function deletePermissionForUser(string $user, string ...$permission): bool
    {
        $params = array_merge([$user], $permission);

        return $this->removePolicy(...$params);
    }

    /**
     * Deletes permissions for a user or role.
     * Returns false if the user or role does not have any permissions (aka not affected).
     *
     * @param string $user
     *
     * @return bool
     */
    public function deletePermissionsForUser(string $user): bool
    {
        return $this->removeFilteredPolicy(0, $user);
    }

    /**
     * Gets permissions for a user or role.
     *
     * @param string $user
     * @param string ...$domain
     *
     * @return array
     */
    public function getPermissionsForUser(string $user, string ...$domain): array
    {
        $permission = [];
        foreach ($this->model['p'] as $ptype => $assertion) {
            $args = [];
            $args[0] = $user;
            foreach ($assertion->tokens as $i => $token) {
                if ($token == sprintf('%s_dom', $ptype)) {
                    $args[$i] = $domain[0];
                    break;
                }
            }
            $perm = $this->getFilteredPolicy(0, ...$args);
            $permission = array_merge($permission, $perm);
        }
        return $permission;
    }

    /**
     * Determines whether a user has a permission.
     *
     * @param string $user
     * @param string ...$permission
     *
     * @return bool
     */
    public function hasPermissionForUser(string $user, string ...$permission): bool
    {
        $params = array_merge([$user], $permission);

        return $this->hasPolicy($params);
    }

    /**
     * Gets implicit roles that a user has.
     * Compared to getRolesForUser(), this function retrieves indirect roles besides direct roles.
     * For example:
     * g, alice, role:admin
     * g, role:admin, role:user.
     *
     * getRolesForUser("alice") can only get: ["role:admin"].
     * But getImplicitRolesForUser("alice") will get: ["role:admin", "role:user"].
     *
     * @param string $name
     * @param string ...$domain
     *
     * @return array
     */
    public function getImplicitRolesForUser(string $name, string ...$domain): array
    {
        $res = [];
        $roleSet = [];
        $roleSet[$name] = true;

        $q = [];
        $q[] = $name;

        for (; count($q) > 0;) {
            $name = $q[0];
            $q = array_slice($q, 1);

            foreach ($this->rmMap as $rm) {
                $roles = $rm->getRoles($name, ...$domain);
                foreach ($roles as $r) {
                    if (!isset($roleSet[$r])) {
                        $res[] = $r;
                        $q[] = $r;
                        $roleSet[$r] = true;
                    }
                }
            }
        }

        return $res;
    }

    /**
     * GetImplicitUsersForRole gets implicit users for a role.
     *
     * @param string $name
     * @param string ...$domain
     * @return array
     */
    public function getImplicitUsersForRole(string $name, string ...$domain): array
    {
        $res = [];
        $roleSet = [];
        $roleSet[$name] = true;

        $q = [];
        $q[] = $name;

        for (; count($q) > 0;) {
            $name = $q[0];
            $q = array_slice($q, 1);

            foreach ($this->rmMap as $rm) {
                $roles = $rm->getUsers($name, ...$domain);
                foreach ($roles as $r) {
                    if (!isset($roleSet[$r])) {
                        $res[] = $r;
                        $q[] = $r;
                        $roleSet[$r] = true;
                    }
                }
            }
        }
        return $res;
    }

    /**
     * GetImplicitResourcesForUser returns all policies that user obtaining in domain
     *
     * @param string $user
     * @param string ...$domain
     * @return array
     */
    public function getImplicitResourcesForUser(string $user, string ...$domain): array
    {
        $permissions = $this->getImplicitPermissionsForUser($user, ...$domain);
        
        $res = [];
        foreach ($permissions as $permission) {
            if ($permission[0] == $user) {
                $res[] = $permission;
                continue;
            }
            $resLocal = [[$user]];
            $tokensLength = count($permission);
            $t = [[]];
            foreach (array_slice($permission, 1) as $token) {
                $tokens = $this->getImplicitUsersForRole($token, ...$domain);
                $tokens[] = $token;
                $t[] = $tokens;
            }

            for ($i = 1; $i < $tokensLength; $i++) {
                $n = [];
                foreach ($t[$i] as $tokens) {
                    foreach ($resLocal as $policy) {
                        $temp = [];
                        $temp = array_merge($temp, $policy);
                        $temp[] = $tokens;
                        $n[] = $temp;
                    }
                }
                $resLocal = $n;
            }
            $res = array_merge($res, $resLocal);
        }
        return $res;
    }

    /**
     * Gets implicit permissions for a user or role.
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
     * @param string ...$domain
     *
     * @return array
     * @throws CasbinException
     */
    public function getImplicitPermissionsForUser(string $user, string ...$domain): array
    {
        $roles = array_merge(
            [$user],
            $this->getImplicitRolesForUser($user, ...$domain)
        );

        $len = \count($domain);
        if ($len > 1) {
            throw new CasbinException('error: domain should be 1 parameter');
        }

        $res = [];
        foreach ($roles as $role) {
            if (1 == $len) {
                $permissions = $this->getPermissionsForUserInDomain($role, $domain[0]);
            } else {
                $permissions = $this->getPermissionsForUser($role);
            }

            $res = array_merge($res, $permissions);
        }

        return $res;
    }

    /**
     * Gets implicit users for a permission.
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
     * @throws CasbinException
     */
    public function getImplicitUsersForPermission(string ...$permission): array
    {
        $pSubjects = $this->getAllSubjects();
        $gInherit = $this->model->getValuesForFieldInPolicyAllTypes("g", 1);
        $gSubjects = $this->model->getValuesForFieldInPolicyAllTypes("g", 0);

        $subjects = array_merge($pSubjects, $gSubjects);
        Util::ArrayRemoveDuplicates($subjects);

        $subjects = array_diff($subjects, $gInherit);

        $res = [];
        foreach ($subjects as $user) {
            $req = $permission;
            array_unshift($req, $user);
            $allowed = $this->enforce(...$req);

            if ($allowed) {
                $res[] = $user;
            }
        }

        return $res;
    }

    /**
     * GetAllUsersByDomain would get all users associated with the domain.
     *
     * @param string $domain
     * @return string[]
     */
    public function getAllUsersByDomain(string $domain): array
    {
        $m = [];
        $g = $this->model['g']['g'];
        $p = $this->model['p']['p'];
        $users = [];
        $index = $this->getDomainIndex('p');

        $getUser = function (int $index, array $policies, string $domain, array $m): array {
            if (count($policies) == 0 || count($policies[0]) <= $index) {
                return [];
            }
            $res = [];
            foreach ($policies as $policy) {
                $ok = isset($m[$policy[0]]);
                if ($policy[$index] == $domain && !$ok) {
                    $res[] = $policy[0];
                    $m[$policy[0]] = [];
                }
            }
            return $res;
        };

        $users = array_merge($users, $getUser(2, $g->policy, $domain, $m));
        $users = array_merge($users, $getUser($index, $p->policy, $domain, $m));
        return $users;
    }

    /**
     * Gets the users that has a role inside a domain. Add by Gordon.
     *
     * @param string $name
     * @param string $domain
     *
     * @return array
     */
    public function getUsersForRoleInDomain(string $name, string $domain): array
    {
        return $this->model['g']['g']->rm->getUsers($name, $domain);
    }

    /**
     * Gets the roles that a user has inside a domain.
     *
     * @param string $name
     * @param string $domain
     *
     * @return array
     */
    public function getRolesForUserInDomain(string $name, string $domain): array
    {
        return $this->model['g']['g']->rm->getRoles($name, $domain);
    }

    /**
     * Gets permissions for a user or role inside a domain.
     *
     * @param string $name
     * @param string $domain
     *
     * @return array
     */
    public function getPermissionsForUserInDomain(string $name, string $domain): array
    {
        return $this->getFilteredPolicy(0, $name, $domain);
    }

    /**
     * Adds a role for a user inside a domain.
     * returns false if the user already has the role (aka not affected).
     *
     * @param string $user
     * @param string $role
     * @param string $domain
     *
     * @return bool
     */
    public function addRoleForUserInDomain(string $user, string $role, string $domain): bool
    {
        return $this->addGroupingPolicy($user, $role, $domain);
    }

    /**
     * Deletes a role for a user inside a domain.
     * Returns false if the user does not have the role (aka not affected).
     *
     * @param string $user
     * @param string $role
     * @param string $domain
     *
     * @return bool
     */
    public function deleteRoleForUserInDomain(string $user, string $role, string $domain): bool
    {
        return $this->removeGroupingPolicy($user, $role, $domain);
    }

    /**
     * DeleteRolesForUserInDomain deletes all roles for a user inside a domain.
     * Returns false if the user does not have any roles (aka not affected).
     *
     * @param string $user
     * @param string $domain
     *
     * @return bool
     */
    public function deleteRolesForUserInDomain(string $user, string $domain): bool
    {
        $roles = $this->model['g']['g']->rm->getRoles($user, $domain);

        $rules = [];
        foreach ($roles as $role) {
            $rules[] = [$user, $role, $domain];
        }

        return $this->removeGroupingPolicies($rules);
    }

    /**
     * DeleteAllUsersByDomain would delete all users associated with the domain.
     *
     * @param string $domain
     * @return bool
     */
    public function deleteAllUsersByDomain(string $domain): bool
    {
        $g = $this->model['g']['g'];
        $p = $this->model['p']['p'];
        $index = $this->getDomainIndex('p');

        $getUser = function (int $index, array $policies, string $domain): array {
            if (count($policies) == 0 || count($policies[0]) <= $index) {
                return [];
            }
            $res = [];
            foreach ($policies as $policy) {
                if ($policy[$index] == $domain) {
                    $res[] = $policy;
                }
            }
            return $res;
        };

        $users = $getUser(2, $g->policy, $domain);
        $this->removeGroupingPolicies($users);
        $users = $getUser($index, $p->policy, $domain);
        $this->removePolicies($users);
        return true;
    }

    /**
     * DeleteDomains would delete all associated users and roles.
     * It would delete all domains if parameter is not provided.
     *
     * @param string ...$domains
     * @return bool
     */
    public function deleteDomains(string ...$domains): bool
    {
        if (count($domains) == 0) {
            $this->clearPolicy();
            return true;
        }
        foreach ($domains as $domain) {
            $this->deleteAllUsersByDomain($domain);
        }
        return true;
    }
}
