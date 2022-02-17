<?php

namespace Casbin\Tests\Unit;

use Casbin\Rbac\DefaultRoleManager\RoleManager;
use Casbin\Util\BuiltinOperations;
use PHPUnit\Framework\TestCase;
use Casbin\Enforcer;
use Casbin\Persist\Adapters\FileAdapter;

/**
 * EnforcerTest.
 *
 * @author techlee@qq.com
 */
class EnforcerTest extends TestCase
{
    private $modelAndPolicyPath = __DIR__ . '/../../examples';

    public function testGetRolesForUser()
    {
        $e = new Enforcer($this->modelAndPolicyPath . '/rbac_model.conf', $this->modelAndPolicyPath . '/rbac_policy.csv');
        $this->assertEquals($e->getRolesForUser('alice'), ['data2_admin']);
        $this->assertEquals($e->getRolesForUser('bob'), []);
        $this->assertEquals($e->getRolesForUser('data2_admin'), []);
        $this->assertEquals($e->getRolesForUser('non_exist'), []);

        $e = new Enforcer($this->modelAndPolicyPath . '/rbac_with_domains_model.conf', $this->modelAndPolicyPath . '/rbac_with_domains_policy.csv');

        $this->assertEquals(['admin'], $e->getRolesForUser('alice', 'domain1'));
        $this->assertEquals([], $e->getRolesForUser('bob', 'domain1'));
        $this->assertEquals([], $e->getRolesForUser('admin', 'domain1'));
        $this->assertEquals([], $e->getRolesForUser('non_exist', 'domain1'));
        $this->assertEquals([], $e->getRolesForUser('alice', 'domain2'));
        $this->assertEquals(['admin'], $e->getRolesForUser('bob', 'domain2'));
        $this->assertEquals([], $e->getRolesForUser('admin', 'domain2'));
        $this->assertEquals([], $e->getRolesForUser('non_exist', 'domain2'));
    }

    public function testGetUsersForRole()
    {
        $e = new Enforcer($this->modelAndPolicyPath . '/rbac_model.conf', $this->modelAndPolicyPath . '/rbac_policy.csv');
        $this->assertEquals($e->getUsersForRole('data2_admin'), ['alice']);
    }

    public function testHasRoleForUser()
    {
        $e = new Enforcer($this->modelAndPolicyPath . '/rbac_model.conf', $this->modelAndPolicyPath . '/rbac_policy.csv');
        $this->assertTrue($e->hasRoleForUser('alice', 'data2_admin'));
        $this->assertFalse($e->hasRoleForUser('alice', 'data1_admin'));

        $e = new Enforcer($this->modelAndPolicyPath . '/rbac_with_domains_model.conf', $this->modelAndPolicyPath . '/rbac_with_domains_policy.csv');
        $this->assertTrue($e->hasRoleForUser('alice', 'admin', 'domain1'));
        $this->assertFalse($e->hasRoleForUser('alice', 'admin', 'domain2'));
    }

    public function testAddRoleForUser()
    {
        $e = new Enforcer($this->modelAndPolicyPath . '/rbac_model.conf', $this->modelAndPolicyPath . '/rbac_policy.csv');
        $e->addRoleForUser('alice', 'data1_admin');
        $this->assertEquals($e->getRolesForUser('alice'), ['data2_admin', 'data1_admin']);

        $e = new Enforcer($this->modelAndPolicyPath . '/rbac_with_domains_model.conf', $this->modelAndPolicyPath . '/rbac_with_domains_policy.csv');
        $this->assertTrue($e->hasRoleForUser('alice', 'admin', 'domain1'));
        $this->assertFalse($e->hasRoleForUser('bob', 'admin', 'domain1'));

        $e->deleteRoleForUser('alice', 'admin', 'domain1');
        $e->addRoleForUser('bob', 'admin', 'domain1');

        $this->assertEquals([], $e->getRolesForUser('alice', 'domain1'));
        $this->assertEquals(['admin'], $e->getRolesForUser('bob', 'domain1'));
        $this->assertEquals(['admin'], $e->getRolesForUser('bob', 'domain2'));

        $this->assertEquals([], $e->getRolesForUser('non_exist', 'domain1'));
        $this->assertEquals([], $e->getRolesForUser('non_exist', 'domain2'));
    }

    public function testAddRolesForUser()
    {
        $e = new Enforcer($this->modelAndPolicyPath . '/rbac_model.conf', $this->modelAndPolicyPath . '/rbac_policy.csv');
        $e->addRolesForUser('alice', ["data1_admin", "data2_admin", "data3_admin"]);
        // The "alice" already has "data2_admin" , it will be return false. So "alice" just has "data2_admin".
        $this->assertEquals(["data2_admin"], $e->getRolesForUser('alice'));

        $e->deleteRoleForUser('alice', 'data2_admin');
        $e->addRolesForUser('alice', ["data1_admin", "data2_admin", "data3_admin"]);
        $this->assertEquals(["data1_admin", "data2_admin", "data3_admin"], $e->getRolesForUser('alice'));
        $this->assertTrue($e->enforce('alice', 'data1', 'read'));
        $this->assertTrue($e->enforce('alice', 'data2', 'read'));
        $this->assertTrue($e->enforce('alice', 'data2', 'write'));
    }

    public function testDeleteRoleForUser()
    {
        $e = new Enforcer($this->modelAndPolicyPath . '/rbac_model.conf', $this->modelAndPolicyPath . '/rbac_policy.csv');
        $e->addRoleForUser('alice', 'data1_admin');
        $this->assertEquals($e->getRolesForUser('alice'), ['data2_admin', 'data1_admin']);

        $e->deleteRoleForUser('alice', 'data1_admin');
        $this->assertEquals($e->getRolesForUser('alice'), ['data2_admin']);

        $e = new Enforcer($this->modelAndPolicyPath . '/rbac_with_domains_model.conf', $this->modelAndPolicyPath . '/rbac_with_domains_policy.csv');
        $this->assertTrue($e->hasRoleForUser('alice', 'admin', 'domain1'));
        $this->assertFalse($e->hasRoleForUser('bob', 'admin', 'domain1'));

        $e->deleteRoleForUser('alice', 'admin', 'domain1');
        $e->addRoleForUser('bob', 'admin', 'domain1');

        $this->assertFalse($e->hasRoleForUser('alice', 'admin', 'domain1'));
        $this->assertTrue($e->hasRoleForUser('bob', 'admin', 'domain1'));
    }

    public function testDeleteRolesForUser()
    {
        $e = new Enforcer($this->modelAndPolicyPath . '/rbac_model.conf', $this->modelAndPolicyPath . '/rbac_policy.csv');
        $e->deleteRolesForUser('alice');
        $this->assertEquals($e->getRolesForUser('alice'), []);
    }

    public function testDeleteRolesForUserInDomain()
    {
        $e = new Enforcer($this->modelAndPolicyPath . '/rbac_with_domains_model.conf', $this->modelAndPolicyPath . '/rbac_with_domains_policy.csv');

        $this->assertEquals($e->getRolesForUser('bob', 'domain2'), ['admin']);
        $e->deleteRolesForUserInDomain('bob', 'domain2');
        $this->assertEquals($e->getRolesForUser('bob', 'domain2'), []);

        $this->assertEquals($e->getRolesForUser('alice', 'domain1'), ['admin']);
        $e->deleteRolesForUserInDomain('alice', 'domain1');
        $this->assertEquals($e->getRolesForUser('alice', 'domain1'), []);

        $e->addRoleForUserInDomain('bob', 'admin', 'domain1');
        $this->assertEquals($e->getRolesForUser('bob', 'domain1'), ['admin']);
        $e->deleteRolesForUserInDomain('bob', 'domain1');
        $this->assertEquals($e->getRolesForUser('bob', 'domain1'), []);
    }

    public function testDeleteUser()
    {
        $e = new Enforcer($this->modelAndPolicyPath . '/rbac_model.conf', $this->modelAndPolicyPath . '/rbac_policy.csv');
        $this->assertTrue($e->hasPolicy('alice', 'data1', 'read'));
        $this->assertEquals($e->getRolesForUser('alice'), ['data2_admin']);

        $e->deleteUser('alice');
        $this->assertFalse($e->hasPolicy('alice', 'data1', 'read'));
        $this->assertEquals($e->getRolesForUser('alice'), []);
    }

    public function testDeleteRole()
    {
        $e = new Enforcer($this->modelAndPolicyPath . '/rbac_model.conf', $this->modelAndPolicyPath . '/rbac_policy.csv');
        $e->deleteRole('data2_admin');
        $this->assertTrue($e->enforce('alice', 'data1', 'read'));
        $this->assertFalse($e->enforce('alice', 'data1', 'write'));
        $this->assertFalse($e->enforce('alice', 'data2', 'read'));
        $this->assertFalse($e->enforce('alice', 'data2', 'write'));
        $this->assertFalse($e->enforce('bob', 'data1', 'read'));
        $this->assertFalse($e->enforce('bob', 'data1', 'write'));
        $this->assertFalse($e->enforce('bob', 'data2', 'read'));
        $this->assertTrue($e->enforce('bob', 'data2', 'write'));
    }

    public function testDeletePermission()
    {
        $e = new Enforcer($this->modelAndPolicyPath . '/basic_without_resources_model.conf', $this->modelAndPolicyPath . '/basic_without_resources_policy.csv');
        $e->deletePermission('read');
        $this->assertFalse($e->enforce('alice', 'read'));
        $this->assertFalse($e->enforce('alice', 'write'));
        $this->assertFalse($e->enforce('bob', 'read'));
        $this->assertTrue($e->enforce('bob', 'write'));
    }

    public function testAddPermissionForUser()
    {
        $e = new Enforcer($this->modelAndPolicyPath . '/basic_without_resources_model.conf', $this->modelAndPolicyPath . '/basic_without_resources_policy.csv');
        $e->deletePermission('read');
        $e->addPermissionForUser('bob', 'read');
        $this->assertTrue($e->enforce('bob', 'read'));
        $this->assertTrue($e->enforce('bob', 'write'));
    }

    public function testAddPermissionsForUser()
    {
        $e = new Enforcer($this->modelAndPolicyPath . '/basic_without_resources_model.conf', $this->modelAndPolicyPath . '/basic_without_resources_policy.csv');
        $e->addPermissionsForUser('jack', ['read'], ['write']);
        $this->assertTrue($e->enforce('jack', 'read'));
        $this->assertTrue($e->enforce('jack', 'write'));
    }

    public function testDeletePermissionForUser()
    {
        $e = new Enforcer($this->modelAndPolicyPath . '/basic_without_resources_model.conf', $this->modelAndPolicyPath . '/basic_without_resources_policy.csv');
        $e->addPermissionForUser('bob', 'read');
        $this->assertTrue($e->enforce('bob', 'read'));

        $e->deletePermissionForUser('bob', 'read');
        $this->assertFalse($e->enforce('bob', 'read'));
        $this->assertTrue($e->enforce('bob', 'write'));
    }

    public function testDeletePermissionsForUser()
    {
        $e = new Enforcer($this->modelAndPolicyPath . '/basic_without_resources_model.conf', $this->modelAndPolicyPath . '/basic_without_resources_policy.csv');
        $e->deletePermissionsForUser('bob');
        $this->assertTrue($e->enforce('alice', 'read'));
        $this->assertFalse($e->enforce('bob', 'read'));
        $this->assertFalse($e->enforce('bob', 'write'));
    }

    public function testGetPermissionsForUser()
    {
        $e = new Enforcer($this->modelAndPolicyPath . '/basic_without_resources_model.conf', $this->modelAndPolicyPath . '/basic_without_resources_policy.csv');
        $this->assertEquals($e->getPermissionsForUser('alice'), [['alice', 'read']]);
    }

    public function testHasPermissionForUser()
    {
        $e = new Enforcer($this->modelAndPolicyPath . '/basic_without_resources_model.conf', $this->modelAndPolicyPath . '/basic_without_resources_policy.csv');
        $this->assertTrue($e->hasPermissionForUser('alice', ...['read']));
        $this->assertFalse($e->hasPermissionForUser('alice', ...['write']));
        $this->assertFalse($e->hasPermissionForUser('bob', ...['read']));
        $this->assertTrue($e->hasPermissionForUser('bob', ...['write']));
    }

    public function testGetImplicitRolesForUser()
    {
        $e = new Enforcer($this->modelAndPolicyPath . '/rbac_model.conf', $this->modelAndPolicyPath . '/rbac_with_hierarchy_policy.csv');

        $this->assertEquals($e->getPermissionsForUser('alice'), [['alice', 'data1', 'read']]);
        $this->assertEquals($e->getPermissionsForUser('bob'), [['bob', 'data2', 'write']]);

        $this->assertEquals($e->getImplicitRolesForUser('alice'), ['admin', 'data1_admin', 'data2_admin']);
        $this->assertEquals($e->getImplicitRolesForUser('bob'), []);

        $e = new Enforcer($this->modelAndPolicyPath . '/rbac_with_domains_model.conf', $this->modelAndPolicyPath . '/rbac_with_hierarchy_with_domains_policy.csv');
        $this->assertEquals($e->getImplicitRolesForUser('alice', 'domain1'), ['role:global_admin', 'role:reader', 'role:writer']);

        $e = new Enforcer($this->modelAndPolicyPath . '/rbac_with_pattern_model.conf', $this->modelAndPolicyPath . '/rbac_with_pattern_policy.csv');

        $roleManager = $e->getRoleManager();
        if ($roleManager instanceof RoleManager) {
            $roleManager->addMatchingFunc('matcher', function (string $key1, string $key2) {
                return BuiltinOperations::keyMatch($key1, $key2);
            });
        }

        $this->assertEquals($e->getImplicitRolesForUser('cathy'), ['/book/1/2/3/4/5', 'pen_admin']);
        $this->assertEquals($e->getRolesForUser('cathy'), ['/book/1/2/3/4/5', 'pen_admin']);
    }
    
    public function testGetImplicitResourcesForUser()
    {
        $e = new Enforcer($this->modelAndPolicyPath . '/rbac_with_pattern_model.conf', $this->modelAndPolicyPath . '/rbac_with_pattern_policy.csv');
        $this->assertEqualsCanonicalizing([
            ["alice", "/pen/1", "GET"],
            ["alice", "/pen2/1", "GET"],
            ["alice", "/book/:id", "GET"],
            ["alice", "/book2/{id}", "GET"],
            ["alice", "/book/*", "GET"],
            ["alice", "book_group", "GET"],
        ], $e->getImplicitResourcesForUser('alice'));

        $this->assertEqualsCanonicalizing([
            ["bob", "pen_group", "GET"],
            ["bob", "/pen/:id", "GET"],
            ["bob", "/pen2/{id}", "GET"],
        ], $e->getImplicitResourcesForUser('bob'));

        $this->assertEqualsCanonicalizing([
            ["cathy", "pen_group", "GET"],
            ["cathy", "/pen/:id", "GET"],
            ["cathy", "/pen2/{id}", "GET"],
        ], $e->getImplicitResourcesForUser('cathy'));
    }

    public function testImplicitUsersForRole()
    {
        $e = new Enforcer($this->modelAndPolicyPath . '/rbac_with_pattern_model.conf', $this->modelAndPolicyPath . '/rbac_with_pattern_policy.csv');

        $this->assertEqualsCanonicalizing(['alice'], $e->getImplicitUsersForRole('book_admin'));
        $this->assertEqualsCanonicalizing(['cathy', 'bob'], $e->getImplicitUsersForRole('pen_admin'));
        $this->assertEqualsCanonicalizing(['/book/*', '/book/:id', '/book2/{id}'], $e->getImplicitUsersForRole('book_group'));
        $this->assertEqualsCanonicalizing(['/pen/:id', '/pen2/{id}'], $e->getImplicitUsersForRole('pen_group'));
    }

    public function testGetImplicitPermissionsForUser()
    {
        $e = new Enforcer($this->modelAndPolicyPath . '/rbac_model.conf', $this->modelAndPolicyPath . '/rbac_with_hierarchy_policy.csv');
        $this->assertEquals($e->getImplicitPermissionsForUser('alice'), [
            ['alice', 'data1', 'read'],
            ['data1_admin', 'data1', 'read'],
            ['data1_admin', 'data1', 'write'],
            ['data2_admin', 'data2', 'read'],
            ['data2_admin', 'data2', 'write'],
        ]);
        $this->assertEquals($e->getImplicitPermissionsForUser('bob'), [
            ['bob', 'data2', 'write'],
        ]);

        $e = new Enforcer($this->modelAndPolicyPath . '/rbac_with_domains_model.conf', $this->modelAndPolicyPath . '/rbac_with_hierarchy_with_domains_policy.csv');
        $this->assertEquals($e->getImplicitPermissionsForUser('alice', 'domain1'), [
            ['alice', 'domain1', 'data2', 'read'],
            ['role:reader', 'domain1', 'data1', 'read'],
            ['role:writer', 'domain1', 'data1', 'write'],
        ]);
    }

    public function testGetImplicitUsersForPermission()
    {
        $e = new Enforcer($this->modelAndPolicyPath . '/rbac_model.conf', $this->modelAndPolicyPath . '/rbac_with_hierarchy_policy.csv');
        $this->assertEquals($e->getImplicitUsersForPermission('data1', 'read'), ['alice']);
        $this->assertEquals($e->getImplicitUsersForPermission('data1', 'write'), ['alice']);
        $this->assertEquals($e->getImplicitUsersForPermission('data2', 'read'), ['alice']);
        $this->assertEquals($e->getImplicitUsersForPermission('data2', 'write'), ['alice', 'bob']);
    }

    public function testGetUsersForRoleInDomain()
    {
        $e = new Enforcer($this->modelAndPolicyPath . '/rbac_with_domains_model.conf', $this->modelAndPolicyPath . '/rbac_with_domains_policy.csv');

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
        $e = new Enforcer($this->modelAndPolicyPath . '/rbac_with_domains_model.conf', $this->modelAndPolicyPath . '/rbac_with_domains_policy.csv');

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
        $e = new Enforcer($this->modelAndPolicyPath . '/rbac_with_domains_model.conf', $this->modelAndPolicyPath . '/rbac_with_domains_policy.csv');

        $this->assertEquals($e->getPermissionsForUserInDomain('alice', 'domain1'), []);
        $this->assertEquals($e->getPermissionsForUserInDomain('bob', 'domain1'), []);
        $this->assertEquals($e->getPermissionsForUserInDomain('admin', 'domain1'), [['admin', 'domain1', 'data1', 'read'], ['admin', 'domain1', 'data1', 'write']]);
        $this->assertEquals($e->getPermissionsForUserInDomain('non_exist', 'domain1'), []);

        $this->assertEquals($e->getPermissionsForUserInDomain('alice', 'domain2'), []);
        $this->assertEquals($e->getPermissionsForUserInDomain('bob', 'domain2'), []);
        $this->assertEquals($e->getPermissionsForUserInDomain('admin', 'domain2'), [['admin', 'domain2', 'data2', 'read'], ['admin', 'domain2', 'data2', 'write']]);
        $this->assertEquals($e->getPermissionsForUserInDomain('non_exist', 'domain2'), []);
    }

    public function testGetAllUsersByDomain()
    {
        $e = new Enforcer($this->modelAndPolicyPath . '/rbac_with_domains_model.conf', $this->modelAndPolicyPath . '/rbac_with_domains_policy.csv');

        $this->assertEquals(['alice', 'admin'], $e->getAllUsersByDomain('domain1'));
        $this->assertEquals(['bob', 'admin'], $e->getAllUsersByDomain('domain2'));
    }

    public function testFailedToLoadPolicy()
    {
        $e = new Enforcer($this->modelAndPolicyPath . '/rbac_with_pattern_model.conf', $this->modelAndPolicyPath . '/rbac_with_pattern_policy.csv');
        $e->addNamedMatchingFunc('g2', 'matchingFunc', function (string $key1, string $key2) {
            return BuiltinOperations::keyMatch2($key1, $key2);
        });
        $this->assertTrue($e->enforce('alice', '/pen/1', 'GET'));
        $this->assertTrue($e->enforce('alice', '/pen2/1', 'GET'));
        $e->setAdapter(new FileAdapter('not found'));
        $e->loadPolicy();
        $this->assertTrue($e->enforce('alice', '/pen/1', 'GET'));
        $this->assertTrue($e->enforce('alice', '/pen2/1', 'GET'));
    }

    public function testReloadPolicyWithFunc()
    {
        $e = new Enforcer($this->modelAndPolicyPath . '/rbac_with_pattern_model.conf', $this->modelAndPolicyPath . '/rbac_with_pattern_policy.csv');
        $e->addNamedMatchingFunc('g2', 'matchingFunc', function (string $key1, string $key2) {
            return BuiltinOperations::keyMatch2($key1, $key2);
        });
        $this->assertTrue($e->enforce('alice', '/pen/1', 'GET'));
        $this->assertTrue($e->enforce('alice', '/pen2/1', 'GET'));
        $e->loadPolicy();
        $this->assertTrue($e->enforce('alice', '/pen/1', 'GET'));
        $this->assertTrue($e->enforce('alice', '/pen2/1', 'GET'));
    }

    public function testBatchEnforce()
    {
        $e = new Enforcer($this->modelAndPolicyPath . '/basic_model.conf', $this->modelAndPolicyPath . '/basic_policy.csv');

        $res = $e->batchEnforce([
            ['alice', 'data1', 'read'],
            ['bob', 'data2', 'write'],
            ['jack', 'data3', 'read']
        ]);
        $this->assertEquals([true, true, false], $res);
    }

    public function testSubjectPriority()
    {
        $e = new Enforcer($this->modelAndPolicyPath . '/subject_priority_model.conf', $this->modelAndPolicyPath . '/subject_priority_policy.csv');
        $this->assertTrue($e->enforce('jane', 'data1', 'read'));
        $this->assertTrue($e->enforce('alice', 'data1', 'read'));
    }

    public function testSubjectPriorityWithDomain()
    {
        $e = new Enforcer($this->modelAndPolicyPath . '/subject_priority_model_with_domain.conf', $this->modelAndPolicyPath . '/subject_priority_policy_with_domain.csv');
        $this->assertTrue($e->enforce('alice', 'data1', 'domain1', 'write'));
        $this->assertTrue($e->enforce('bob', 'data2', 'domain2', 'write'));
    }

    public function testDeleteAllUsersByDomain()
    {
        $e = new Enforcer($this->modelAndPolicyPath . '/rbac_with_domains_model.conf', $this->modelAndPolicyPath . '/rbac_with_domains_policy.csv');
    
        $e->deleteAllUsersByDomain('domain1');
        $this->assertEquals([
            ['admin', 'domain2', 'data2', 'read'],
            ['admin', 'domain2', 'data2', 'write'],
        ], $e->getPolicy());
        $this->assertEquals([
            ['bob', 'admin', 'domain2']
        ], $e->getGroupingPolicy());

        $e = new Enforcer($this->modelAndPolicyPath . '/rbac_with_domains_model.conf', $this->modelAndPolicyPath . '/rbac_with_domains_policy.csv');
        $e->deleteAllUsersByDomain('domain2');
        $this->assertEquals([
            ['admin', 'domain1', 'data1', 'read'],
            ['admin', 'domain1', 'data1', 'write'],
        ], $e->getPolicy());
        $this->assertEquals([
            ['alice', 'admin', 'domain1']
        ], $e->getGroupingPolicy());
    }

    public function testDeleteDomains()
    {
        $e = new Enforcer($this->modelAndPolicyPath . '/rbac_with_domains_model.conf', $this->modelAndPolicyPath . '/rbac_with_domains_policy.csv');

        $e->deleteDomains();
        $this->assertEquals([], $e->getPolicy());
        $this->assertEquals([], $e->getGroupingPolicy());

        $e = new Enforcer($this->modelAndPolicyPath . '/rbac_with_domains_model.conf', $this->modelAndPolicyPath . '/rbac_with_domains_policy.csv');

        $e->deleteDomains('domain1');
        $this->assertEquals([
            ['admin', 'domain2', 'data2', 'read'],
            ['admin', 'domain2', 'data2', 'write'],
        ], $e->getPolicy());
        $this->assertEquals([
            ['bob', 'admin', 'domain2']
        ], $e->getGroupingPolicy());

        $e = new Enforcer($this->modelAndPolicyPath . '/rbac_with_domains_model.conf', $this->modelAndPolicyPath . '/rbac_with_domains_policy.csv');

        $e->deleteDomains('domain1', 'domain2');
        $this->assertEquals([], $e->getPolicy());
        $this->assertEquals([], $e->getGroupingPolicy());
    }
}
