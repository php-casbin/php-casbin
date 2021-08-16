<?php

namespace Casbin\Tests\Unit;

use Casbin\Exceptions\BatchOperationException;
use PHPUnit\Framework\TestCase;
use Casbin\Enforcer;
use Casbin\Persist\Adapters\FileAdapter;
use Casbin\Tests\Watcher\SampleWatcher;
use Casbin\Tests\Watcher\SampleWatcherUpdatable;
use Mockery;
use Casbin\Exceptions\NotImplementedException;

/**
 * ManagementEnforcerTest.
 *
 * @author techlee@qq.com
 */
class ManagementEnforcerTest extends TestCase
{
    private $modelAndPolicyPath = __DIR__ . '/../../examples';

    public function testGetAllNamedSubjects()
    {
        $e = new Enforcer($this->modelAndPolicyPath . '/rbac_model.conf', $this->modelAndPolicyPath . '/rbac_policy.csv');
        $this->assertEquals(['alice', 'bob', 'data2_admin'], $e->getAllNamedSubjects('p'));
        $this->assertEquals([], $e->getAllNamedSubjects('g'));
    }


    public function testGetAllNamedObjects()
    {
        $e = new Enforcer($this->modelAndPolicyPath . '/rbac_model.conf', $this->modelAndPolicyPath . '/rbac_policy.csv');
        $this->assertEquals(['data1', 'data2'], $e->getAllNamedObjects('p'));
        $this->assertEquals([], $e->getAllNamedObjects('g'));
    }

    public function testGetAllNamedActions()
    {
        $e = new Enforcer($this->modelAndPolicyPath . '/rbac_model.conf', $this->modelAndPolicyPath . '/rbac_policy.csv');
        $this->assertEquals(['read', 'write'], $e->getAllNamedActions('p'));
    }

    public function testGetAllNamedRoles()
    {
        $e = new Enforcer($this->modelAndPolicyPath . '/rbac_model.conf', $this->modelAndPolicyPath . '/rbac_policy.csv');
        $this->assertEquals(['data2_admin'], $e->getAllNamedRoles('g'));
    }

    public function testGetList()
    {
        $e = new Enforcer($this->modelAndPolicyPath . '/rbac_model.conf', $this->modelAndPolicyPath . '/rbac_policy.csv');

        $this->assertEquals($e->getAllSubjects(), ['alice', 'bob', 'data2_admin']);
        $this->assertEquals($e->getAllObjects(), ['data1', 'data2']);
        $this->assertEquals($e->getAllActions(), ['read', 'write']);
        $this->assertEquals($e->getAllRoles(), ['data2_admin']);
    }

    public function testGetPolicyAPI()
    {
        $e = new Enforcer($this->modelAndPolicyPath . '/rbac_model.conf', $this->modelAndPolicyPath . '/rbac_policy.csv');

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
        $e = new Enforcer($this->modelAndPolicyPath . '/rbac_model.conf', $this->modelAndPolicyPath . '/rbac_policy.csv');

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

        $rules = [
            ['jack', 'data4', 'read'],
            ['katy', 'data4', 'write'],
            ['leyo', 'data4', 'read'],
            ['ham', 'data4', 'write'],
        ];

        $e->addPolicies($rules);
        $e->addPolicies($rules);

        $this->assertEquals([
            ['data2_admin', 'data2', 'read'],
            ['data2_admin', 'data2', 'write'],
            ['eve', 'data3', 'read'],
            ['jack', 'data4', 'read'],
            ['katy', 'data4', 'write'],
            ['leyo', 'data4', 'read'],
            ['ham', 'data4', 'write'],
        ], $e->getPolicy());

        $e->removePolicies($rules);
        $e->removePolicies($rules);

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

    public function testModifyGroupingPolicyAPI()
    {
        $e = new Enforcer($this->modelAndPolicyPath . '/rbac_model.conf', $this->modelAndPolicyPath . '/rbac_policy.csv');

        $this->assertEquals($e->getRolesForUser('alice'), ['data2_admin']);
        $this->assertEquals($e->getRolesForUser('bob'), []);
        $this->assertEquals($e->getRolesForUser('env'), []);
        $this->assertEquals($e->getRolesForUser('non_exist'), []);

        $result = $e->removeGroupingPolicy('alice', 'data2_admin');
        $e->addGroupingPolicy('bob', 'data1_admin');
        $e->addGroupingPolicy('eve', 'data3_admin');

        $groupingRules = [
            ['ham', 'data4_admin'],
            ['jack', 'data5_admin'],
        ];

        $e->addGroupingPolicies($groupingRules);
        $this->assertEquals($e->getRolesForUser('ham'), ['data4_admin']);
        $this->assertEquals($e->getRolesForUser('jack'), ['data5_admin']);
        $e->removeGroupingPolicies($groupingRules);

        $this->assertEquals($e->getRolesForUser('alice'), []);
        $nameGroupingPolicy = ['alice', 'data2_admin'];
        $this->assertEquals($e->getRolesForUser('alice'), []);
        $e->addNamedGroupingPolicy('g', $nameGroupingPolicy);
        $this->assertEquals($e->getRolesForUser('alice'), ['data2_admin']);
        $e->removeNamedGroupingPolicy('g', $nameGroupingPolicy);

        $e->addNamedGroupingPolicies('g', $groupingRules);
        $e->addNamedGroupingPolicies('g', $groupingRules);
        $this->assertEquals($e->getRolesForUser('ham'), ['data4_admin']);
        $this->assertEquals($e->getRolesForUser('jack'), ['data5_admin']);
        $e->removeNamedGroupingPolicies('g', $groupingRules);
        $e->removeNamedGroupingPolicies('g', $groupingRules);

        $this->assertEquals($e->getRolesForUser('alice'), []);
        $this->assertEquals($e->getRolesForUser('bob'), ['data1_admin']);
        $this->assertEquals($e->getRolesForUser('eve'), ['data3_admin']);
        $this->assertEquals($e->getRolesForUser('non_exist'), []);

        $this->assertEquals($e->getUsersForRole('data1_admin'), ['bob']);
        $this->assertEquals($e->getUsersForRole('data2_admin'), []);
        $this->assertEquals($e->getUsersForRole('data3_admin'), ['eve']);

        $e->removeFilteredGroupingPolicy(0, 'bob');

        $this->assertEquals($e->getRolesForUser('alice'), []);
        $this->assertEquals($e->getRolesForUser('bob'), []);
        $this->assertEquals($e->getRolesForUser('eve'), ['data3_admin']);
        $this->assertEquals($e->getRolesForUser('non_exist'), []);

        $this->assertEquals($e->getUsersForRole('data1_admin'), []);
        $this->assertEquals($e->getUsersForRole('data2_admin'), []);
        $this->assertEquals($e->getUsersForRole('data3_admin'), ['eve']);
    }

    public function testUpdatePolicy()
    {
        // p, alice, data1, read
        // p, bob, data2, write
        // p, data2_admin, data2, read
        // p, data2_admin, data2, write
        //
        // g, alice, data2_admin

        $e = new Enforcer($this->modelAndPolicyPath . '/rbac_model.conf', $this->modelAndPolicyPath . '/rbac_policy.csv');

        $this->assertTrue($e->hasPolicy('alice', 'data1', 'read'));
        $this->assertFalse($e->hasPolicy('alice', 'data1', 'write'));

        $e->updatePolicy(['alice', 'data1', 'read'], ['alice', 'data1', 'write']);

        $this->assertFalse($e->hasPolicy('alice', 'data1', 'read'));
        $this->assertTrue($e->hasPolicy('alice', 'data1', 'write'));
    }

    public function testUpdatePolicies()
    {
        // p, alice, data1, read
        // p, bob, data2, write
        // p, data2_admin, data2, read
        // p, data2_admin, data2, write
        //
        // g, alice, data2_admin

        $e = new Enforcer($this->modelAndPolicyPath . '/rbac_model.conf', $this->modelAndPolicyPath . '/rbac_policy.csv');
        $watcherUpdatable = new SampleWatcherUpdatable();
        $e->setWatcher($watcherUpdatable);

        $this->assertTrue($e->hasPolicy('alice', 'data1', 'read'));
        $this->assertFalse($e->hasPolicy('alice', 'data1', 'write'));
        $this->assertTrue($e->hasPolicy('bob', 'data2', 'write'));
        $this->assertFalse($e->hasPolicy('bob', 'data2', 'read'));

        $oldPolicies = [
            ['alice', 'data1', 'read'],
            ['bob', 'data2', 'write']
        ];
        $newPolicies = [
            ['alice', 'data1', 'write'],
            ['bob', 'data2', 'read']
        ];
        $e->updatePolicies($newPolicies, $oldPolicies);
        $watcherUpdatable->setUpdateCallback(function () {
            throw new \Exception('');
        });
        $e->updatePolicies($oldPolicies, $newPolicies);

        $this->assertFalse($e->hasPolicy('alice', 'data1', 'read'));
        $this->assertTrue($e->hasPolicy('alice', 'data1', 'write'));
        $this->assertFalse($e->hasPolicy('bob', 'data2', 'write'));
        $this->assertTrue($e->hasPolicy('bob', 'data2', 'read'));
        $watcher = new SampleWatcher();
        $e->setWatcher($watcher);
        $watcher->setUpdateCallback(function () {
        });
        $e->updatePolicies($newPolicies, $oldPolicies);
    }

    public function testupdateFilteredPolicies()
    {
        // p, alice, data1, read
        // p, bob, data2, write
        // p, data2_admin, data2, read
        // p, data2_admin, data2, write
        //
        // g, alice, data2_admin

        $testAdapter = Mockery::mock(FileAdapter::class);
        $model = Mockery::type("Casbin\Model\Model");
        $testAdapter->shouldReceive('loadPolicy')->once()->with($model)->andReturn(null);
    
        $e = new Enforcer($this->modelAndPolicyPath . '/rbac_model.conf', $testAdapter);
        $rules = [
            ['alice', 'data1', 'read'],
            ['bob', 'data2', 'write']
        ];

        $testAdapter->shouldReceive('addPolicies')->once()->with('p', 'p', $rules)->andReturn(null);
        $e->addPolicies($rules);

        $watcherUpdatable = new SampleWatcherUpdatable();
        $e->setWatcher($watcherUpdatable);
        $watcherUpdatable->setUpdateCallback(function () {
        });

        $this->assertTrue($e->hasPolicy('alice', 'data1', 'read'));
        $this->assertFalse($e->hasPolicy('alice', 'data1', 'write'));
        $this->assertTrue($e->hasPolicy('bob', 'data2', 'write'));
        $this->assertFalse($e->hasPolicy('bob', 'data2', 'read'));

        $testAdapter->shouldReceive('updateFilteredPolicies')->once()->with('p', 'p', [['alice', 'data1', 'write']], 0, 'alice', 'data1', 'read')->andReturn([['alice', 'data1', 'read']]);
        $e->updateFilteredPolicies([['alice', 'data1', 'write']], 0, 'alice', 'data1', 'read');
        $testAdapter->shouldReceive('updateFilteredPolicies')->once()->with('p', 'p', [['bob', 'data2', 'read']], 0, 'bob', 'data2', 'write')->andReturn([['bob', 'data2', 'write']]);
        $e->updateFilteredPolicies([['bob', 'data2', 'read']], 0, 'bob', 'data2', 'write');

        $this->assertFalse($e->hasPolicy('alice', 'data1', 'read'));
        $this->assertTrue($e->hasPolicy('alice', 'data1', 'write'));
        $this->assertFalse($e->hasPolicy('bob', 'data2', 'write'));
        $this->assertTrue($e->hasPolicy('bob', 'data2', 'read'));

        $watcher = new SampleWatcher();
        $e->setWatcher($watcher);
        $watcher->setUpdateCallback(function () {
        });
        
        $testAdapter->shouldReceive('updateFilteredPolicies')->once()->with('p', 'p', [['alice', 'data1', 'read']], 0, 'alice', 'data1', 'write')->andReturn([['alice', 'data1', 'write']]);
        $e->updateFilteredPolicies([['alice', 'data1', 'read']], 0, 'alice', 'data1', 'write');
        $this->assertFalse($e->hasPolicy('alice', 'data1', 'write'));
        $this->assertTrue($e->hasPolicy('alice', 'data1', 'read'));
    }

    public function testupdateFilteredPoliciesWithoutWatcher()
    {
        $testAdapter = Mockery::mock(FileAdapter::class);
        $model = Mockery::type("Casbin\Model\Model");
        $testAdapter->shouldReceive('loadPolicy')->once()->with($model)->andReturn(null);
    
        $e = new Enforcer($this->modelAndPolicyPath . '/rbac_model.conf', $testAdapter);
        $rules = [
            ['alice', 'data1', 'read'],
        ];
        $testAdapter->shouldReceive('addPolicies')->once()->with('p', 'p', $rules)->andReturn(null);
        
        $e->addPolicies($rules);


        $this->assertTrue($e->hasPolicy('alice', 'data1', 'read'));
        $this->assertFalse($e->hasPolicy('alice', 'data1', 'write'));

        // throw exception
        $testAdapter->shouldReceive('updateFilteredPolicies')->once()->with('p', 'p', [['alice', 'data1', 'write']], 0, 'alice', 'data1', 'read')->andReturn([['alice', 'data1', 'read']])->andThrow(new NotImplementedException());

        $e->updateFilteredPolicies([['alice', 'data1', 'write']], 0, 'alice', 'data1', 'read');

        $testAdapter->shouldReceive('updateFilteredPolicies')->once()->with('p', 'p', [['alice', 'data1', 'write']], 0, 'alice', 'data1', 'read')->andReturn([['alice', 'data1', 'read']]);

        $e->updateFilteredPolicies([['alice', 'data1', 'write']], 0, 'alice', 'data1', 'read');

        // if $ruleChanged is 0
        $testAdapter->shouldReceive('updateFilteredPolicies')->once()->with('p', 'p', [], 0, 'alice', 'data1', 'read')->andReturn([['alice', 'data1', 'read']]);

        $e->updateFilteredPolicies([], 0, 'alice', 'data1', 'read');

        $this->assertFalse($e->hasPolicy('alice', 'data1', 'read'));
        $this->assertTrue($e->hasPolicy('alice', 'data1', 'write'));
    }
}
