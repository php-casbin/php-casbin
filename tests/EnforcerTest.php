<?php

namespace Casbin\Tests;

use Casbin\Enforcer;
use Casbin\Model\Model;
use Casbin\Persist\Adapters\FileAdapter;
use PHPUnit\Framework\TestCase;

/**
 * CoreEnforcerTest.
 *
 * @author techlee@qq.com
 */
class EnforcerTest extends TestCase
{
    private $modelAndPolicyPath = __DIR__ . '/../examples';

    public function testKeyMatchModelInMemory()
    {
        $m = Model::newModel();
        $m->addDef('r', 'r', 'sub, obj, act');
        $m->addDef('p', 'p', 'sub, obj, act');
        $m->addDef('e', 'e', 'some(where (p.eft == allow))');
        $m->addDef('m', 'm', 'r.sub == p.sub && keyMatch(r.obj, p.obj) && regexMatch(r.act, p.act)');

        $a = new FileAdapter($this->modelAndPolicyPath . '/keymatch_policy.csv');

        $e = new Enforcer($m, $a);

        $this->assertTrue($e->enforce('alice', '/alice_data/resource1', 'GET'));
        $this->assertFalse($e->enforce('bob', '/alice_data/resource1', 'GET'));

        $e = new Enforcer($m);
        $this->assertTrue($e->enforce('alice', '/alice_data/resource1', 'GET'));
        $this->assertFalse($e->enforce('bob', '/alice_data/resource1', 'GET'));
    }

    public function testKeyMatchModelInMemoryDeny()
    {
        $m = Model::newModel();
        $m->addDef('r', 'r', 'sub, obj, act');
        $m->addDef('p', 'p', 'sub, obj, act');
        $m->addDef('e', 'e', '!some(where (p.eft == deny))');
        $m->addDef('m', 'm', 'r.sub == p.sub && keyMatch(r.obj, p.obj) && regexMatch(r.act, p.act)');

        $a = new FileAdapter($this->modelAndPolicyPath . '/keymatch_policy.csv');

        $e = new Enforcer($m, $a);

        $this->assertTrue($e->enforce('alice', '/alice_data/resource1', 'GET'));
    }

    public function testRBACModelInMemoryIndeterminate()
    {
        $m = Model::newModel();
        $m->addDef('r', 'r', 'sub, obj, act');
        $m->addDef('p', 'p', 'sub, obj, act');
        $m->addDef('g', 'g', '_, _');
        $m->addDef('e', 'e', 'some(where (p.eft == allow))');
        $m->addDef('m', 'm', 'g(r.sub, p.sub) && r.obj == p.obj && r.act == p.act');

        $e = new Enforcer($m);

        $e->addPermissionForUser('alice', 'data1', 'invalid');

        $this->assertFalse($e->enforce('alice', 'data1', 'read'));
    }

    public function testEnforceBasic()
    {
        $e = new Enforcer($this->modelAndPolicyPath . '/basic_model.conf', $this->modelAndPolicyPath . '/basic_policy.csv');

        $this->assertEquals($e->enforce('alice', 'data1', 'read'), true);
        $this->assertEquals($e->enforce('alice', 'data2', 'read'), false);
        $this->assertEquals($e->enforce('bob', 'data2', 'write'), true);
        $this->assertEquals($e->enforce('bob', 'data1', 'write'), false);
    }

    public function testEnforceBasicNoPolicy()
    {
        $e = new Enforcer($this->modelAndPolicyPath . '/basic_model.conf');

        $this->assertEquals($e->enforce('alice', 'data1', 'read'), false);
        $this->assertEquals($e->enforce('alice', 'data2', 'read'), false);
        $this->assertEquals($e->enforce('bob', 'data2', 'write'), false);
        $this->assertEquals($e->enforce('bob', 'data1', 'write'), false);
    }

    public function testEnforceBasicWithRoot()
    {
        $e = new Enforcer($this->modelAndPolicyPath . '/basic_with_root_model.conf', $this->modelAndPolicyPath . '/basic_policy.csv');

        $this->assertEquals($e->enforce('root', 'any', 'any'), true);
    }

    public function testEnforceBasicWithRootNoPolicy()
    {
        $e = new Enforcer($this->modelAndPolicyPath . '/basic_with_root_model.conf');
        $this->assertFalse($e->enforce('alice', 'data1', 'read'));
        $this->assertFalse($e->enforce('alice', 'data1', 'write'));
        $this->assertFalse($e->enforce('alice', 'data2', 'read'));
        $this->assertFalse($e->enforce('alice', 'data2', 'write'));
        $this->assertFalse($e->enforce('bob', 'data1', 'read'));
        $this->assertFalse($e->enforce('bob', 'data1', 'write'));
        $this->assertFalse($e->enforce('bob', 'data2', 'read'));
        $this->assertFalse($e->enforce('bob', 'data2', 'write'));
        $this->assertTrue($e->enforce('root', 'data1', 'read'));
        $this->assertTrue($e->enforce('root', 'data1', 'write'));
        $this->assertTrue($e->enforce('root', 'data2', 'read'));
        $this->assertTrue($e->enforce('root', 'data2', 'write'));
    }

    public function testEnforceBasicWithoutResources()
    {
        $e = new Enforcer($this->modelAndPolicyPath . '/basic_without_resources_model.conf', $this->modelAndPolicyPath . '/basic_without_resources_policy.csv');

        $this->assertEquals($e->enforce('alice', 'read'), true);
        $this->assertEquals($e->enforce('alice', 'write'), false);
        $this->assertEquals($e->enforce('bob', 'write'), true);
        $this->assertEquals($e->enforce('bob', 'read'), false);
    }

    public function testEnforceBasicWithoutUsers()
    {
        $e = new Enforcer($this->modelAndPolicyPath . '/basic_without_users_model.conf', $this->modelAndPolicyPath . '/basic_without_users_policy.csv');

        $this->assertEquals($e->enforce('data1', 'read'), true);
        $this->assertEquals($e->enforce('data1', 'write'), false);
        $this->assertEquals($e->enforce('data2', 'write'), true);
        $this->assertEquals($e->enforce('data2', 'read'), false);
    }

    public function testEnforceIpMatch()
    {
        $e = new Enforcer($this->modelAndPolicyPath . '/ipmatch_model.conf', $this->modelAndPolicyPath . '/ipmatch_policy.csv');

        $this->assertEquals($e->enforce('192.168.2.1', 'data1', 'read'), true);
        $this->assertEquals($e->enforce('192.168.3.1', 'data1', 'read'), false);
    }

    public function testEnforceKeyMatch()
    {
        $e = new Enforcer($this->modelAndPolicyPath . '/keymatch_model.conf', $this->modelAndPolicyPath . '/keymatch_policy.csv');

        $this->assertEquals($e->enforce('alice', '/alice_data/test', 'GET'), true);
        $this->assertEquals($e->enforce('alice', '/bob_data/test', 'GET'), false);
        $this->assertEquals($e->enforce('cathy', '/cathy_data', 'GET'), true);
        $this->assertEquals($e->enforce('cathy', '/cathy_data', 'POST'), true);
        $this->assertEquals($e->enforce('cathy', '/cathy_data/12', 'POST'), false);
    }

    public function testEnforceKeyMatch2()
    {
        $e = new Enforcer($this->modelAndPolicyPath . '/keymatch2_model.conf', $this->modelAndPolicyPath . '/keymatch2_policy.csv');

        $this->assertEquals($e->enforce('alice', '/alice_data/resource', 'GET'), true);
        $this->assertEquals($e->enforce('alice', '/alice_data2/123/using/456', 'GET'), true);
    }

    public function testEnforcePriority()
    {
        $e = new Enforcer($this->modelAndPolicyPath . '/priority_model.conf', $this->modelAndPolicyPath . '/priority_policy.csv');

        $this->assertEquals($e->enforce('alice', 'data1', 'read'), true);
        $this->assertEquals($e->enforce('alice', 'data1', 'write'), false);
        $this->assertEquals($e->enforce('alice', 'data2', 'read'), false);
        $this->assertEquals($e->enforce('alice', 'data2', 'read'), false);

        $this->assertEquals($e->enforce('bob', 'data1', 'read'), false);
        $this->assertEquals($e->enforce('bob', 'data1', 'write'), false);
        $this->assertEquals($e->enforce('bob', 'data2', 'read'), true);
        $this->assertEquals($e->enforce('bob', 'data2', 'write'), false);
    }

    public function testEnforcePriorityIndeterminate()
    {
        $e = new Enforcer($this->modelAndPolicyPath . '/priority_model.conf', $this->modelAndPolicyPath . '/priority_indeterminate_policy.csv');

        $this->assertEquals($e->enforce('alice', 'data1', 'read'), false);
    }

    public function testEnforceRbac()
    {
        $e = new Enforcer($this->modelAndPolicyPath . '/rbac_model.conf', $this->modelAndPolicyPath . '/rbac_policy.csv');
        $this->assertEquals($e->enforce('alice', 'data1', 'read'), true);
        $this->assertEquals($e->enforce('bob', 'data2', 'write'), true);
        $this->assertEquals($e->enforce('alice', 'data2', 'read'), true);
        $this->assertEquals($e->enforce('alice', 'data2', 'write'), true);
    }

    public function testEnforceRbacWithDeny()
    {
        $e = new Enforcer($this->modelAndPolicyPath . '/rbac_with_deny_model.conf', $this->modelAndPolicyPath . '/rbac_with_deny_policy.csv');
        $this->assertEquals($e->enforce('alice', 'data1', 'read'), true);
        $this->assertEquals($e->enforce('bob', 'data2', 'write'), true);
        $this->assertEquals($e->enforce('alice', 'data2', 'read'), true);
        $this->assertEquals($e->enforce('alice', 'data2', 'write'), false);
    }

    public function testEnforceRbacWithDomains()
    {
        $e = new Enforcer($this->modelAndPolicyPath . '/rbac_with_domains_model.conf', $this->modelAndPolicyPath . '/rbac_with_domains_policy.csv');

        $this->assertEquals($e->enforce('alice', 'domain1', 'data1', 'read'), true);
        $this->assertEquals($e->enforce('alice', 'domain1', 'data1', 'write'), true);
        $this->assertEquals($e->enforce('alice', 'domain1', 'data2', 'read'), false);
        $this->assertEquals($e->enforce('alice', 'domain1', 'data2', 'write'), false);
        $this->assertEquals($e->enforce('bob', 'domain2', 'data1', 'read'), false);
        $this->assertEquals($e->enforce('bob', 'domain2', 'data1', 'write'), false);
        $this->assertEquals($e->enforce('bob', 'domain2', 'data2', 'read'), true);
        $this->assertEquals($e->enforce('bob', 'domain2', 'data2', 'write'), true);
    }

    public function testEnforceRbacWithNotDeny()
    {
        $e = new Enforcer($this->modelAndPolicyPath . '/rbac_with_not_deny_model.conf', $this->modelAndPolicyPath . '/rbac_with_deny_policy.csv');

        $this->assertEquals($e->enforce('alice', 'data2', 'write'), false);
    }

    public function testEnforceRbacWithResourceRoles()
    {
        $e = new Enforcer($this->modelAndPolicyPath . '/rbac_with_resource_roles_model.conf', $this->modelAndPolicyPath . '/rbac_with_resource_roles_policy.csv');

        $this->assertEquals($e->enforce('alice', 'data1', 'read'), true);
        $this->assertEquals($e->enforce('alice', 'data1', 'write'), true);
        $this->assertEquals($e->enforce('alice', 'data2', 'read'), false);
        $this->assertEquals($e->enforce('alice', 'data2', 'write'), true);
        $this->assertEquals($e->enforce('bob', 'data1', 'read'), false);
        $this->assertEquals($e->enforce('bob', 'data1', 'write'), false);
        $this->assertEquals($e->enforce('bob', 'data2', 'read'), false);
        $this->assertEquals($e->enforce('bob', 'data2', 'write'), true);
    }
}
