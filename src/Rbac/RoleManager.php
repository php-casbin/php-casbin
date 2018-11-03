<?php

namespace Casbin\Rbac;

/**
 * RoleManager.
 *
 * @author techlee@qq.com
 */
interface RoleManager
{
    public function clear();

    public function addLink($name1, $name2, ...$domain);

    public function deleteLink($name1, $name2, ...$domain);

    public function hasLink($name1, $name2, ...$domain);

    public function getRoles($name, ...$domain);

    public function getUsers($name, ...$domain);

    public function printRoles();
}
