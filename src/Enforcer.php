<?php

declare(strict_types=1);

namespace Casbin;

use Casbin\Constant\Constants;
use Casbin\Exceptions\CasbinException;
use Casbin\Exceptions\EmptyConditionException;
use Casbin\Exceptions\ObjConditionException;
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
     * @return string[]|null
     */
    public function getRolesForUser(string $name, string ...$domain): ?array
    {
        return isset($this->model['g']['g']) ? $this->model['g']['g']->rm?->getRoles($name, ...$domain) : [];
    }

    /**
     * Gets the users that has a role.
     *
     * @param string $name
     * @param string ...$domain
     *
     * @return string[]|null
     */
    public function getUsersForRole(string $name, string ...$domain): ?array
    {
        return isset($this->model['g']['g']) ? $this->model['g']['g']->rm?->getUsers($name, ...$domain) : [];
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

        return in_array($role, $roles ?? [], true);
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

        $subIndex = $this->model->getFieldIndex('p', Constants::SUBJECT_INDEX);
        $res2 = $this->removeFilteredPolicy($subIndex, $user);

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

        $subIndex = $this->model->getFieldIndex('p', Constants::SUBJECT_INDEX);
        $res2 = $this->removeFilteredPolicy($subIndex, $role);

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
     * @param array ...$permissions
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
        $subIndex = $this->model->getFieldIndex('p', Constants::SUBJECT_INDEX);
        return $this->removeFilteredPolicy($subIndex, $user);
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
        foreach ($this->model['p'] ?? [] as $ptype => $assertion) {
            $args = [];
            $subIndex = $this->model->getFieldIndex('p', Constants::SUBJECT_INDEX);
            $args[$subIndex] = $user;
            if (count($domain) > 0) {
                $domIndex = $this->model->getFieldIndex($ptype, Constants::DOMAIN_INDEX);
                $args[$domIndex] = $domain[0];
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
     * GetDomainsForUser gets all domains that a subject inherits.
     *
     * @param string $user
     *
     * @return string[]
     */
    public function getDomainsForUser(string $user): array
    {
        $domains = [];
        foreach ($this->rmMap as $rm) {
            $res = $rm->getDomains($user);
            $domains = array_merge($domains, $res);
        }

        return $domains;
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

        $len = count($domain);
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
     * Convert permissions to string as a hash to deduplicate.
     *
     * @param array $permissions
     *
     * @return array
     */
    private function removeDumplicatePermissions(array $permissions): array
    {
        $permissionsSet = [];
        $res = [];

        foreach ($permissions as $permission) {
            $permissionStr = Util::arrayToString($permission);

            if (isset($permissionsSet[$permissionStr])) {
                continue;
            }

            $permissionsSet[$permissionStr] = true;
            $res[] = $permission;
        }
        return $res;
    }

    /**
     * GetAllowedObjectConditions returns a string array of object conditions that the user can access.
     * For example: conditions, err := e.GetAllowedObjectConditions("alice", "read", "r.obj.")
     * Note:
     *
     * 0. prefix: You can customize the prefix of the object conditions, and "r.obj." is commonly used as a prefix.
     * After removing the prefix, the remaining part is the condition of the object.
     * If there is an obj policy that does not meet the prefix requirement, an ObjConditionException will be thrown.
     *
     * 1. If the 'objectConditions' array is empty, an EmptyConditionException will be thrown.
     * This error is thrown because some data adapters' ORM return full table data by default
     * when they receive an empty condition, which tends to behave contrary to expectations.(e.g. DBALAdapter)
     * If you are using an adapter that does not behave like this, you can choose to ignore this error.
     *
     * @param string $user
     * @param string $action
     * @param string $prefix
     *
     * @return array
     * @throws ObjConditionException
     * @throws EmptyConditionException
     */
    public function getAllowedObjectConditions(string $user, string $action, string $prefix): array
    {
        $permission = $this->getImplicitPermissionsForUser($user);

        $objectConditions = [];
        foreach ($permission as $policy) {
            if ($policy[2] == $action) {
                if (!str_starts_with($policy[1], $prefix)) {
                    throw new ObjConditionException('need to meet the prefix required by the object condition');
                }

                $objectConditions[] = substr($policy[1], strlen($prefix));
            }
        }

        if (empty($objectConditions)) {
            throw new EmptyConditionException('GetAllowedObjectConditions have an empty condition');
        }

        return $objectConditions;
    }

    /**
     * GetImplicitUsersForResource return implicit user based on resource.
     * For example:
     * p, alice, data1, read
     * p, bob, data2, write
     * p, data2_admin, data2, read
     * p, data2_admin, data2, write
     * g, alice, data2_admin
     * GetImplicitUsersForResource("data2") will return [[bob data2 write] [alice data2 read] [alice data2 write]]
     * GetImplicitUsersForResource("data1") will return [[alice data1 read]]
     * Note: only users will be returned, roles (2nd arg in "g") will be excluded.
     *
     * @param string $resource
     *
     * @return array
     */
    public function getImplicitUsersForResource(string $resource): array
    {
        $permissions = [];
        $subIndex = $this->model->getFieldIndex('p', Constants::SUBJECT_INDEX);
        $objIndex = $this->model->getFieldIndex('p', Constants::OBJECT_INDEX);
        $rm = $this->getRoleManager();

        $roles = $this->getAllRoles();
        $isRole = array_flip($roles);

        if (!isset($this->model['p']['p'])) {
            return $permissions;
        }

        foreach ($this->model['p']['p']->policy as $rule) {
            $obj = $rule[$objIndex];
            if ($obj != $resource) {
                continue;
            }

            $sub = $rule[$subIndex];

            if (!isset($isRole[$sub])) {
                $permissions[] = $rule;
            } else {
                $users = $rm->getUsers($sub);

                foreach ($users as $user) {
                    $implicitRule = array_merge([], $rule);
                    $implicitRule[$subIndex] = $user;
                    $permissions[] = $implicitRule;
                }
            }
        }

        return $this->removeDumplicatePermissions($permissions);
    }

    /**
     * GetImplicitUsersForResourceByDomain return implicit user based on resource and domain.
     * Compared to GetImplicitUsersForResource, domain is supported.
     *
     * @param string $resource
     * @param string $domain
     *
     * @return array
     */
    public function getImplicitUsersForResourceByDomain(string $resource, string $domain): array
    {
        $permissions = [];
        $subIndex = $this->model->getFieldIndex('p', Constants::SUBJECT_INDEX);
        $objIndex = $this->model->getFieldIndex('p', Constants::OBJECT_INDEX);
        $domIndex = $this->model->getFieldIndex('p', Constants::DOMAIN_INDEX);
        $rm = $this->getRoleManager();

        $roles = $this->getAllRolesByDomain($domain);
        $isRole = array_flip($roles);

        if (!isset($this->model['p']['p'])) {
            return $permissions;
        }

        foreach ($this->model['p']['p']->policy as $rule) {
            $obj = $rule[$objIndex];
            if ($obj != $resource) {
                continue;
            }

            $sub = $rule[$subIndex];

            if (!isset($isRole[$sub])) {
                $permissions[] = $rule;
            } else {
                if ($rule[$domIndex] != $domain) {
                    continue;
                }

                $users = $rm->getUsers($sub, $domain);
                foreach ($users as $user) {
                    $implicitRule = array_merge([], $rule);
                    $implicitRule[$subIndex] = $user;
                    $permissions[] = $implicitRule;
                }
            }
        }

        return $this->removeDumplicatePermissions($permissions);
    }

    /**
     * GetAllUsersByDomain would get all users associated with the domain.
     *
     * @param string $domain
     * @return string[]
     * @throws CasbinException
     */
    public function getAllUsersByDomain(string $domain): array
    {
        $m = [];
        $g = $this->model['g']['g'] ?? null;
        $p = $this->model['p']['p'] ?? null;
        $users = [];
        $index = $this->model->getFieldIndex('p', Constants::DOMAIN_INDEX);

        $getUser = function (int $index, ?array $policies, string $domain, array $m): array {
            if (is_null($policies) || count($policies) == 0 || count($policies[0]) <= $index) {
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

        $users = array_merge($users, $getUser(2, $g?->policy, $domain, $m));
        $users = array_merge($users, $getUser($index, $p?->policy, $domain, $m));
        return $users;
    }

    /**
     * Gets the users that has a role inside a domain. Add by Gordon.
     *
     * @param string $name
     * @param string $domain
     *
     * @return array|null
     */
    public function getUsersForRoleInDomain(string $name, string $domain): ?array
    {
        return isset($this->model['g']['g']) ? $this->model['g']['g']->rm?->getUsers($name, $domain) : [];
    }

    /**
     * Gets the roles that a user has inside a domain.
     *
     * @param string $name
     * @param string $domain
     *
     * @return array|null
     */
    public function getRolesForUserInDomain(string $name, string $domain): ?array
    {
        return isset($this->model['g']['g']) ? $this->model['g']['g']->rm?->getRoles($name, $domain) : [];
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
        $roles = isset($this->model['g']['g']) ? $this->model['g']['g']->rm?->getRoles($user, $domain) : [];

        $rules = [];
        foreach ($roles ?? [] as $role) {
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
        $g = $this->model['g']['g'] ?? null;
        $p = $this->model['p']['p'] ?? null;
        $index = $this->model->getFieldIndex('p', Constants::DOMAIN_INDEX);

        $getUser = function (int $index, ?array $policies, string $domain): array {
            if (is_null($policies) || count($policies) == 0 || count($policies[0]) <= $index) {
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

        $users = $getUser(2, $g?->policy, $domain);
        $this->removeGroupingPolicies($users);
        $users = $getUser($index, $p?->policy, $domain);
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

    /**
     * GetAllDomains would get all domains.
     *
     * @return array
     */
    public function getAllDomains(): array
    {
        return $this->getRoleManager()->getAllDomains();
    }

    /**
     * GetAllRolesByDomain would get all roles associated with the domain.
     * Note: Not applicable to Domains with inheritance relationship  (implicit roles)
     *
     * @param string $domain
     *
     * @return array
     */
    public function getAllRolesByDomain(string $domain): array
    {
        $g = $this->model['g']['g'] ?? null;
        $policies = $g ? $g->policy : [];
        $roles = [];
        $existMap = [];

        foreach ($policies as $policy) {
            if ($policy[count($policy) - 1] == $domain) {
                $role = $policy[count($policy) - 2];
                if (!isset($existMap[$role])) {
                    $roles[] = $role;
                    $existMap[$role] = true;
                }
            }
        }

        return $roles;
    }
}
