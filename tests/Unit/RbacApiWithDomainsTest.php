<?php

namespace Casbin\Tests\Unit;

use PHPUnit\Framework\TestCase;
use Casbin\Enforcer;

/**
 * RbacApiWithDomainsTest.
 *
 * @author techlee@qq.com
 */
class RbacApiWithDomainsTest extends TestCase
{
    private $modelAndPolicyPath = __DIR__.'/../../examples';

    public function testGetUsersForRoleInDomain()
    {
        $e = new Enforcer($this->modelAndPolicyPath.'/rbac_with_domains_model.conf', $this->modelAndPolicyPath.'/rbac_with_domains_policy.csv');

        $this->assertEquals($e->getUsersForRoleInDomain('admin', 'domain1'), ['alice']);
        $this->assertEquals($e->getUsersForRoleInDomain('non_exist', 'domain1'), []);

        $this->assertEquals($e->getUsersForRoleInDomain('admin', 'domain2'), ['bob']);
        $this->assertEquals($e->getUsersForRoleInDomain('non_exist', 'domain2'), []);

        $e->deleteRoleForUserInDomain('alice', 'admin', 'domain1');
        $e->addRoleForUserInDomain('bob', 'admin', 'domain1');

        $this->assertEquals($e->getUsersForRoleInDomain('admin', 'domain1'), ['bob']);
        $this->assertEquals($e->getUsersForRoleInDomain('non_exist', 'domain1'), []);

        $this->assertEquals($e->getUsersForRoleInDomain('admin', 'domain2'), ['bob']);
        $this->assertEquals($e->getUsersForRoleInDomain('non_exist', 'domain2'), []);
    }

    public function testGetRolesForUserInDomain()
    {
        $e = new Enforcer($this->modelAndPolicyPath.'/rbac_with_domains_model.conf', $this->modelAndPolicyPath.'/rbac_with_domains_policy.csv');

        $this->assertEquals($e->getRolesForUserInDomain('alice', 'domain1'), ['admin']);
        $this->assertEquals($e->getRolesForUserInDomain('bob', 'domain1'), []);
        $this->assertEquals($e->getRolesForUserInDomain('admin', 'domain1'), []);
        $this->assertEquals($e->getRolesForUserInDomain('non_exist', 'domain1'), []);

        $this->assertEquals($e->getRolesForUserInDomain('alice', 'domain2'), []);
        $this->assertEquals($e->getRolesForUserInDomain('bob', 'domain2'), ['admin']);
        $this->assertEquals($e->getRolesForUserInDomain('admin', 'domain2'), []);
        $this->assertEquals($e->getRolesForUserInDomain('non_exist', 'domain2'), []);

        $e->deleteRoleForUserInDomain('alice', 'admin', 'domain1');
        $e->addRoleForUserInDomain('bob', 'admin', 'domain1');

        $this->assertEquals($e->getRolesForUserInDomain('alice', 'domain1'), []);
        $this->assertEquals($e->getRolesForUserInDomain('bob', 'domain1'), ['admin']);
        $this->assertEquals($e->getRolesForUserInDomain('admin', 'domain1'), []);
        $this->assertEquals($e->getRolesForUserInDomain('non_exist', 'domain1'), []);

        $this->assertEquals($e->getRolesForUserInDomain('alice', 'domain2'), []);
        $this->assertEquals($e->getRolesForUserInDomain('bob', 'domain2'), ['admin']);
        $this->assertEquals($e->getRolesForUserInDomain('admin', 'domain2'), []);
        $this->assertEquals($e->getRolesForUserInDomain('non_exist', 'domain2'), []);
    }

    public function testGetPermissionsForUserInDomain()
    {
        $e = new Enforcer($this->modelAndPolicyPath.'/rbac_with_domains_model.conf', $this->modelAndPolicyPath.'/rbac_with_domains_policy.csv');

        $this->assertEquals($e->getPermissionsForUserInDomain('alice', 'domain1'), []);
        $this->assertEquals($e->getPermissionsForUserInDomain('bob', 'domain1'), []);
        $this->assertEquals($e->getPermissionsForUserInDomain('admin', 'domain1'), [['admin', 'domain1', 'data1', 'read'], ['admin', 'domain1', 'data1', 'write']]);
        $this->assertEquals($e->getPermissionsForUserInDomain('non_exist', 'domain1'), []);

        $this->assertEquals($e->getPermissionsForUserInDomain('alice', 'domain2'), []);
        $this->assertEquals($e->getPermissionsForUserInDomain('bob', 'domain2'), []);
        $this->assertEquals($e->getPermissionsForUserInDomain('admin', 'domain2'), [['admin', 'domain2', 'data2', 'read'], ['admin', 'domain2', 'data2', 'write']]);
        $this->assertEquals($e->getPermissionsForUserInDomain('non_exist', 'domain2'), []);
    }
}
