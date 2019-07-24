<?php

namespace Casbin\Rbac;

/**
 * Interface RoleManager.
 * provides interface to define the operations for managing roles.
 *
 * @author techlee@qq.com
 */
interface RoleManager
{
    /**
     * clears all stored data and resets the role manager to the initial state.
     */
    public function clear();

    /**
     * adds the inheritance link between role: name1 and role: name2.
     * aka role: name1 inherits role: name2.
     * domain is a prefix to the roles.
     *
     * @param string $name1
     * @param string $name2
     * @param string $domain
     */
    public function addLink($name1, $name2, $domain = '');

    /**
     * deletes the inheritance link between role: name1 and role: name2.
     * aka role: name1 does not inherit role: name2 any more.
     * domain is a prefix to the roles.
     *
     * @param string $name1
     * @param string $name2
     * @param string $domain
     */
    public function deleteLink($name1, $name2, $domain = '');

    /**
     * determines whether role: name1 inherits role: name2.
     * domain is a prefix to the roles.
     *
     * @param string $name1
     * @param string $name2
     * @param string $domain
     *
     * @return bool
     */
    public function hasLink($name1, $name2, $domain = '');

    /**
     * gets the roles that a subject inherits.
     * domain is a prefix to the roles.
     *
     * @param string $name
     * @param string $domain
     *
     * @return array
     */
    public function getRoles($name, $domain = '');

    /**
     * gets the users that inherits a subject.
     * domain is an unreferenced parameter here, may be used in other implementations.
     *
     * @param string $name
     * @param string $domain
     *
     * @return array
     */
    public function getUsers($name, $domain = '');

    /**
     * prints all the roles to log.
     */
    public function printRoles();
}
