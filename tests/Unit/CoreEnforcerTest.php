<?php

namespace Casbin\Tests\Unit;

use Casbin\Enforcer;
use Casbin\Exceptions\CasbinException;
use Casbin\Model\Model;
use Casbin\Persist\Adapters\FileAdapter;
use Casbin\Persist\Adapters\FileFilteredAdapter;
use Casbin\Persist\Adapters\Filter;
use Casbin\Rbac\RoleManager;
use PHPUnit\Framework\TestCase;

/**
 * CoreEnforcerTest.
 *
 * @author techlee@qq.com
 */
class CoreEnforcerTest extends TestCase
{
    private $modelAndPolicyPath = __DIR__ . '/../../examples';

    public function testInitWithEnableLog()
    {
        // The log is not enabled by default
        $e = new \Casbin\Enforcer($this->modelAndPolicyPath . '/basic_model.conf', $this->modelAndPolicyPath . '/basic_policy.csv', true);

        $this->assertTrue($e->enforce('alice', 'data1', 'read'));

        // The log can also be enabled or disabled at run-time.
        $e->enableLog(false);
        $this->assertTrue($e->enforce('alice', 'data1', 'read'));
    }

    public function testEnableAutoSave()
    {
        $e = new Enforcer($this->modelAndPolicyPath . '/basic_model.conf', $this->modelAndPolicyPath . '/basic_policy.csv');
        $e->enableAutoSave(false);
        // Because AutoSave is disabled, the policy change only affects the policy in Casbin enforcer,
        // it doesn't affect the policy in the storage.
        $e->removePolicy('alice', 'data1', 'read');
        // Reload the policy from the storage to see the effect.
        $e->loadPolicy();

        $this->assertTrue($e->enforce('alice', 'data1', 'read'));
        $this->assertFalse($e->enforce('alice', 'data1', 'write'));

        $e->enableAutoSave(true);
        // Because AutoSave is enabled, the policy change not only affects the policy in Casbin enforcer,
        // but also affects the policy in the storage.
        $e->removePolicy('alice', 'data1', 'read');
        // However, the file adapter doesn't implement the AutoSave feature, so enabling it has no effect at all here.

        // Reload the policy from the storage to see the effect.
        $e->loadPolicy();

        $this->assertTrue($e->enforce('alice', 'data1', 'read'));
        $this->assertFalse($e->enforce('alice', 'data1', 'write'));
    }

    public function testInitEmpty()
    {
        $e = new Enforcer(true);

        $m = Model::newModelFromString(
            <<<'EOT'
[request_definition]
r = sub, obj, act

[policy_definition]
p = sub, obj, act

[policy_effect]
e = some(where (p.eft == allow))

[matchers]
m = r.sub == p.sub && r.obj == p.obj && r.act == p.act
EOT
        );
        $e->setModel($m);

        $adapter = new FileAdapter($this->modelAndPolicyPath . '/basic_policy.csv');
        $e->setAdapter($adapter);

        $e->loadPolicy();

        $this->assertTrue($e->enforce('alice', 'data1', 'read'));
        $this->assertFalse($e->enforce('alice', 'data2', 'read'));
    }

    public function testGetAndSetModel()
    {
        $e = new Enforcer($this->modelAndPolicyPath . '/basic_model.conf', $this->modelAndPolicyPath . '/basic_policy.csv');
        $e2 = new Enforcer($this->modelAndPolicyPath . '/basic_with_root_model.conf', $this->modelAndPolicyPath . '/basic_policy.csv');

        $this->assertFalse($e->enforce('root', 'data1', 'read'));

        $e->setModel($e2->getModel());

        $this->assertTrue($e->enforce('root', 'data1', 'read'));
    }

    public function testGetAndSetAdapter()
    {
        $e = new Enforcer($this->modelAndPolicyPath . '/basic_model.conf', $this->modelAndPolicyPath . '/basic_policy.csv');
        $e2 = new Enforcer($this->modelAndPolicyPath . '/basic_model.conf', $this->modelAndPolicyPath . '/basic_inverse_policy.csv');

        $this->assertTrue($e->enforce('alice', 'data1', 'read'));
        $this->assertFalse($e->enforce('alice', 'data1', 'write'));

        $a2 = $e2->getAdapter();
        $e->setAdapter($a2);

        $e->loadModel();
        $e->loadPolicy();

        $this->assertFalse($e->enforce('alice', 'data1', 'read'));
        $this->assertTrue($e->enforce('alice', 'data1', 'write'));
    }

    public function testGetRoleManager()
    {
        $e = new Enforcer($this->modelAndPolicyPath . '/rbac_model.conf');
        $rm = $e->getRoleManager();
        $this->assertTrue($rm instanceof RoleManager);
    }

    public function testSetAdapterFromFile()
    {
        $e = new Enforcer($this->modelAndPolicyPath . '/basic_model.conf');
        $adapter = new FileAdapter($this->modelAndPolicyPath . '/basic_policy.csv');

        $e->setAdapter($adapter);
        $e->loadPolicy();

        $this->assertTrue($e->enforce('alice', 'data1', 'read'));
        $this->assertFalse($e->enforce('alice', 'data2', 'read'));
    }

    public function testClearPolicy()
    {
        $e = new Enforcer($this->modelAndPolicyPath . '/rbac_model.conf', $this->modelAndPolicyPath . '/rbac_policy.csv');
        $this->assertTrue($e->enforce('alice', 'data1', 'read'));
        $e->clearPolicy();
        $this->assertFalse($e->enforce('alice', 'data1', 'read'));
    }

    public function testSavePolicy()
    {
        $policyFile = __DIR__ . '/Persist/Adapters/rbac_policy_test.csv';
        file_put_contents($policyFile, '', LOCK_EX);

        $e = new Enforcer($this->modelAndPolicyPath . '/rbac_model.conf', $policyFile);
        $this->assertEquals($e->enforce('alice', 'data1', 'read'), false);
        $this->assertEquals($e->enforce('bob', 'data2', 'write'), false);
        $this->assertEquals($e->enforce('alice', 'data2', 'read'), false);
        $this->assertEquals($e->enforce('alice', 'data2', 'write'), false);

        $m = $e->getModel();
        $m->addPolicy('p', 'p', ['alice', 'data1', 'read']);
        $m->addPolicy('p', 'p', ['bob', 'data2', 'write']);
        $m->addPolicy('p', 'p', ['data2_admin', 'data2', 'read']);
        $m->addPolicy('p', 'p', ['data2_admin', 'data2', 'write']);
        $m->addPolicy('g', 'g', ['alice', 'data2_admin']);
        $e->savePolicy();

        $e2 = new Enforcer($this->modelAndPolicyPath . '/rbac_model.conf', $policyFile);
        $this->assertEquals($e2->enforce('alice', 'data1', 'read'), true);
        $this->assertEquals($e2->enforce('bob', 'data2', 'write'), true);
        $this->assertEquals($e2->enforce('alice', 'data2', 'read'), true);
        $this->assertEquals($e2->enforce('alice', 'data2', 'write'), true);
        file_put_contents($policyFile, '', LOCK_EX);
    }

    public function testFilteredPolicy()
    {
        $adapter = new FileFilteredAdapter($this->modelAndPolicyPath . '/rbac_with_domains_policy.csv');
        $e = new Enforcer($this->modelAndPolicyPath . '/rbac_with_domains_model.conf', $adapter);
        $this->assertTrue($e->isFiltered());

        $e->loadPolicy();

        $this->assertTrue($e->hasPolicy('admin', 'domain1', 'data1', 'read'));
        $this->assertTrue($e->hasPolicy('admin', 'domain2', 'data2', 'read'));

        $e->loadFilteredPolicy(new Filter(
            ['', 'domain1'],
            ['', '', 'domain1']
        ));

        $this->assertTrue($e->hasPolicy('admin', 'domain1', 'data1', 'read'));
        $this->assertFalse($e->hasPolicy('admin', 'domain2', 'data2', 'read'));

        $th = null;

        try {
            $e->savePolicy();
        } catch (\Throwable $th) {
            //throw $th;
        }
        $this->assertInstanceOf(CasbinException::class, $th);

        $th = null;

        try {
            $e->getAdapter()->savePolicy($e->getModel());
        } catch (\Throwable $th) {
            //throw $th;
        }
        $this->assertInstanceOf(CasbinException::class, $th);
    }

    public function testAppendFilteredPolicy()
    {
        $e = new Enforcer();

        $adapter = new FileFilteredAdapter($this->modelAndPolicyPath . '/rbac_with_domains_policy.csv');
        $e->initWithAdapter($this->modelAndPolicyPath . '/rbac_with_domains_model.conf', $adapter);
        $e->loadPolicy();

        // validate initial conditions
        $this->assertTrue($e->hasPolicy('admin', 'domain1', 'data1', 'read'));
        $this->assertTrue($e->hasPolicy('admin', 'domain2', 'data2', 'read'));

        $filter = new Filter();
        $filter->p = ['', 'domain1'];
        $filter->g = ['', '', 'domain1'];
        $e->loadFilteredPolicy($filter);
        $this->assertTrue($adapter->isFiltered());

        // only policies for domain1 should be loaded
        $this->assertTrue($e->hasPolicy('admin', 'domain1', 'data1', 'read'));
        $this->assertFalse($e->hasPolicy('admin', 'domain2', 'data2', 'read'));

        // disable clear policy and load second domain
        $filter = new Filter();
        $filter->p = ['', 'domain2'];
        $filter->g = ['', '', 'domain2'];
        $e->loadIncrementalFilteredPolicy($filter);

        // both domain policies should be loaded
        $this->assertTrue($e->hasPolicy('admin', 'domain1', 'data1', 'read'));
        $this->assertTrue($e->hasPolicy('admin', 'domain2', 'data2', 'read'));
    }

    public function testEnableEnforce()
    {
        $e = new Enforcer($this->modelAndPolicyPath . '/basic_model.conf', $this->modelAndPolicyPath . '/basic_policy.csv');
        $e->enableEnforce(false);

        $this->assertTrue($e->enforce('alice', 'data1', 'read'));
        $this->assertTrue($e->enforce('alice', 'data1', 'read'));
        $this->assertTrue($e->enforce('alice', 'data1', 'write'));
        $this->assertTrue($e->enforce('alice', 'data2', 'read'));
        $this->assertTrue($e->enforce('alice', 'data2', 'write'));
        $this->assertTrue($e->enforce('bob', 'data1', 'read'));
        $this->assertTrue($e->enforce('bob', 'data1', 'write'));
        $this->assertTrue($e->enforce('bob', 'data2', 'read'));
        $this->assertTrue($e->enforce('bob', 'data2', 'write'));

        $e->enableEnforce(true);

        $this->assertTrue($e->enforce('alice', 'data1', 'read'));
        $this->assertFalse($e->enforce('alice', 'data1', 'write'));
        $this->assertFalse($e->enforce('alice', 'data2', 'read'));
        $this->assertFalse($e->enforce('alice', 'data2', 'write'));
        $this->assertFalse($e->enforce('bob', 'data1', 'read'));
        $this->assertFalse($e->enforce('bob', 'data1', 'write'));
        $this->assertFalse($e->enforce('bob', 'data2', 'read'));
        $this->assertTrue($e->enforce('bob', 'data2', 'write'));
    }

    public function testPriorityExplicit()
    {
        $e = new Enforcer($this->modelAndPolicyPath . '/priority_model_explicit.conf', $this->modelAndPolicyPath . '/priority_policy_explicit.csv');
        $this->assertTrue($e->enforce('alice', 'data1', 'write'));
        $this->assertTrue($e->enforce('alice', 'data1', 'read'));
        $this->assertFalse($e->enforce('bob', 'data2', 'read'));
        $this->assertTrue($e->enforce('bob', 'data2', 'write'));
        $this->assertFalse($e->enforce('data1_deny_group', 'data1', 'read'));
        $this->assertFalse($e->enforce('data1_deny_group', 'data1', 'write'));
        $this->assertTrue($e->enforce('data2_allow_group', 'data2', 'read'));
        $this->assertTrue($e->enforce('data2_allow_group', 'data2', 'write'));

        $e->addPolicy('1', 'bob', 'data2', 'write', 'deny');

        $this->assertTrue($e->enforce('alice', 'data1', 'write'));
        $this->assertTrue($e->enforce('alice', 'data1', 'read'));
        $this->assertFalse($e->enforce('bob', 'data2', 'read'));
        $this->assertFalse($e->enforce('bob', 'data2', 'write'));
        $this->assertFalse($e->enforce('data1_deny_group', 'data1', 'read'));
        $this->assertFalse($e->enforce('data1_deny_group', 'data1', 'write'));
        $this->assertTrue($e->enforce('data2_allow_group', 'data2', 'read'));
        $this->assertTrue($e->enforce('data2_allow_group', 'data2', 'write'));
    }
}
