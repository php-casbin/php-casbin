<?php

namespace Casbin;

/**
 * Trait RbacApiWithDomains.
 *
 * @author techlee@qq.com
 */
trait RbacApiWithDomains
{
    /**
     * gets the users that has a role inside a domain. Add by Gordon.
     *
     * @param string $name
     * @param string $domain
     *
     * @return array
     */
    public function getUsersForRoleInDomain($name, $domain)
    {
        return $this->model->model['g']['g']->rM->getUsers($name, $domain);
    }

    /**
     * gets the roles that a user has inside a domain.
     *
     * @param string $name
     * @param string $domain
     *
     * @return array
     */
    public function getRolesForUserInDomain($name, $domain)
    {
        return $this->model->model['g']['g']->rM->getRoles($name, $domain);
    }

    /**
     * gets permissions for a user or role inside a domain.
     *
     * @param string $name
     * @param string $domain
     *
     * @return array
     */
    public function getPermissionsForUserInDomain($name, $domain)
    {
        return $this->getFilteredPolicy(0, $name, $domain);
    }

    /**
     * adds a role for a user inside a domain.
     * returns false if the user already has the role (aka not affected).
     *
     * @param string $user
     * @param string $role
     * @param string $domain
     *
     * @return bool
     */
    public function addRoleForUserInDomain($user, $role, $domain)
    {
        return $this->addGroupingPolicy($user, $role, $domain);
    }

    /**
     * deletes a role for a user inside a domain.
     * returns false if the user does not have the role (aka not affected).
     *
     * @param string $user
     * @param string $role
     * @param string $domain
     *
     * @return bool
     */
    public function deleteRoleForUserInDomain($user, $role, $domain)
    {
        return $this->removeGroupingPolicy($user, $role, $domain);
    }
}
