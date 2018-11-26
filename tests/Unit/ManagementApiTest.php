<?php

namespace Casbin\Tests\Unit;

use PHPUnit\Framework\TestCase;
use Casbin\Enforcer;

/**
 * ManagementApiTest.
 *
 * @author techlee@qq.com
 */
class ManagementApiTest extends TestCase
{
    private $modelAndPolicyPath = __DIR__.'/../../examples';

    public function testGetList()
    {
        $e = new Enforcer($this->modelAndPolicyPath.'/rbac_model.conf', $this->modelAndPolicyPath.'/rbac_policy.csv');

        $this->assertEquals($e->getAllSubjects(), ['alice', 'bob', 'data2_admin']);
        $this->assertEquals($e->getAllObjects(), ['data1', 'data2']);
        $this->assertEquals($e->getAllActions(), ['read', 'write']);
        $this->assertEquals($e->getAllRoles(), ['data2_admin']);
    }

    public function testGetPolicyAPI()
    {
        $e = new Enforcer($this->modelAndPolicyPath.'/rbac_model.conf', $this->modelAndPolicyPath.'/rbac_policy.csv');

        $this->assertEquals($e->getPolicy(), [
            ['alice', 'data1', 'read'],
            ['bob', 'data2', 'write'],
            ['data2_admin', 'data2', 'read'],
            ['data2_admin', 'data2', 'write'],
        ]);

        $this->assertEquals($e->getFilteredPolicy(0, 'alice'), [['alice', 'data1', 'read']]);

        $this->assertEquals($e->getFilteredPolicy(0, 'bob'), [['bob', 'data2', 'write']]);
        $this->assertEquals($e->getFilteredPolicy(0, 'data2_admin'), [['data2_admin', 'data2', 'read'], ['data2_admin', 'data2', 'write']]);
        $this->assertEquals($e->getFilteredPolicy(1, 'data1'), [['alice', 'data1', 'read']]);
        $this->assertEquals($e->getFilteredPolicy(1, 'data2'), [['bob', 'data2', 'write'], ['data2_admin', 'data2', 'read'], ['data2_admin', 'data2', 'write']]);
        $this->assertEquals($e->getFilteredPolicy(2, 'read'), [['alice', 'data1', 'read'], ['data2_admin', 'data2', 'read']]);
        $this->assertEquals($e->getFilteredPolicy(2, 'write'), [['bob', 'data2', 'write'], ['data2_admin', 'data2', 'write']]);

        $this->assertEquals($e->getFilteredPolicy(0, 'data2_admin', 'data2'), [['data2_admin', 'data2', 'read'], ['data2_admin', 'data2', 'write']]);
        // Note: "" (empty string) in fieldValues means matching all values.
        $this->assertEquals($e->getFilteredPolicy(0, 'data2_admin', '', 'read'), [['data2_admin', 'data2', 'read']]);
        $this->assertEquals($e->getFilteredPolicy(1, 'data2', 'write'), [['bob', 'data2', 'write'], ['data2_admin', 'data2', 'write']]);

        $this->assertTrue($e->hasPolicy(['alice', 'data1', 'read']));
        $this->assertTrue($e->hasPolicy(['bob', 'data2', 'write']));
        $this->assertFalse($e->hasPolicy(['alice', 'data2', 'read']));
        $this->assertFalse($e->hasPolicy(['bob', 'data3', 'write']));

        $this->assertEquals($e->getGroupingPolicy(), [['alice', 'data2_admin']]);

        $this->assertEquals($e->getFilteredGroupingPolicy(0, 'alice'), [['alice', 'data2_admin']]);
        $this->assertEquals($e->getFilteredGroupingPolicy(0, 'bob'), []);
        $this->assertEquals($e->getFilteredGroupingPolicy(1, 'data1_admin'), []);
        $this->assertEquals($e->getFilteredGroupingPolicy(1, 'data2_admin'), [['alice', 'data2_admin']]);
        // Note: "" (empty string) in fieldValues means matching all values.
        $this->assertEquals($e->getFilteredGroupingPolicy(0, '', 'data2_admin'), [['alice', 'data2_admin']]);

        $this->assertTrue($e->hasGroupingPolicy(['alice', 'data2_admin']));
        $this->assertFalse($e->hasGroupingPolicy(['bob', 'data2_admin']));
    }

    public function testModifyPolicyAPI()
    {
        $e = new Enforcer($this->modelAndPolicyPath.'/rbac_model.conf', $this->modelAndPolicyPath.'/rbac_policy.csv');

        $this->assertEquals($e->getPolicy(), [
            ['alice', 'data1', 'read'],
            ['bob', 'data2', 'write'],
            ['data2_admin', 'data2', 'read'],
            ['data2_admin', 'data2', 'write'],
        ]);

        $e->removePolicy('alice', 'data1', 'read');
        $e->removePolicy('bob', 'data2', 'write');
        $e->removePolicy('alice', 'data1', 'read');
        $e->addPolicy('eve', 'data3', 'read');
        $e->addPolicy('eve', 'data3', 'read');

        $namedPolicy = ['eve', 'data3', 'read'];
        $e->removeNamedPolicy('p', $namedPolicy);
        $e->addNamedPolicy('p', $namedPolicy);

        $this->assertEquals($e->getPolicy(), [
            ['data2_admin', 'data2', 'read'],
            ['data2_admin', 'data2', 'write'],
            ['eve', 'data3', 'read'],
        ]);

        $e->removeFilteredPolicy(1, 'data2');

        $this->assertEquals($e->getPolicy(), [
            ['eve', 'data3', 'read'],
        ]);
    }
}
