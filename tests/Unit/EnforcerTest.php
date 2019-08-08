<?php

namespace Casbin\Tests\Unit;

use Casbin\Enforcer;
use Casbin\Model\Model;
use Casbin\Persist\Adapters\FileAdapter;
use PHPUnit\Framework\TestCase;

/**
 * EnforcerTest.
 *
 * @author techlee@qq.com
 */
class EnforcerTest extends TestCase
{
    private $modelAndPolicyPath = __DIR__.'/../../examples';

    public function testInitWihtEnableLog()
    {
        // The log is not enabled by default
        $e = new Enforcer($this->modelAndPolicyPath.'/basic_model.conf', $this->modelAndPolicyPath.'/basic_policy.csv', true);

        $this->assertTrue($e->enforce('alice', 'data1', 'read'));

        // The log can also be enabled or disabled at run-time.
        $e->enableLog(false);
        $this->assertTrue($e->enforce('alice', 'data1', 'read'));
    }

    public function testEnableAutoSave()
    {
        $e = new Enforcer($this->modelAndPolicyPath.'/basic_model.conf', $this->modelAndPolicyPath.'/basic_policy.csv');
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

        $adapter = new FileAdapter($this->modelAndPolicyPath.'/basic_policy.csv');
        $e->setAdapter($adapter);

        $e->loadPolicy();

        $this->assertTrue($e->enforce('alice', 'data1', 'read'));
        $this->assertFalse($e->enforce('alice', 'data2', 'read'));
    }

    public function testGetAndSetModel()
    {
        $e = new Enforcer($this->modelAndPolicyPath.'/basic_model.conf', $this->modelAndPolicyPath.'/basic_policy.csv');
        $e2 = new Enforcer($this->modelAndPolicyPath.'/basic_with_root_model.conf', $this->modelAndPolicyPath.'/basic_policy.csv');

        $this->assertFalse($e->enforce('root', 'data1', 'read'));

        $e->setModel($e2->getModel());

        $this->assertTrue($e->enforce('root', 'data1', 'read'));
    }

    public function testGetAndSetAdapter()
    {
        $e = new Enforcer($this->modelAndPolicyPath.'/basic_model.conf', $this->modelAndPolicyPath.'/basic_policy.csv');
        $e2 = new Enforcer($this->modelAndPolicyPath.'/basic_model.conf', $this->modelAndPolicyPath.'/basic_inverse_policy.csv');

        $this->assertTrue($e->enforce('alice', 'data1', 'read'));
        $this->assertFalse($e->enforce('alice', 'data1', 'write'));

        $a2 = $e2->getAdapter();
        $e->setAdapter($a2);

        $e->loadModel();
        $e->loadPolicy();

        $this->assertFalse($e->enforce('alice', 'data1', 'read'));
        $this->assertTrue($e->enforce('alice', 'data1', 'write'));
    }

    public function testSetAdapterFromFile()
    {
        $e = new Enforcer($this->modelAndPolicyPath.'/basic_model.conf');
        $adapter = new FileAdapter($this->modelAndPolicyPath.'/basic_policy.csv');

        $e->setAdapter($adapter);
        $e->loadPolicy();

        $this->assertTrue($e->enforce('alice', 'data1', 'read'));
        $this->assertFalse($e->enforce('alice', 'data2', 'read'));
    }

    public function testClearPolicy()
    {
        $e = new Enforcer($this->modelAndPolicyPath.'/rbac_model.conf', $this->modelAndPolicyPath.'/rbac_policy.csv');
        $this->assertTrue($e->enforce('alice', 'data1', 'read'));
        $e->clearPolicy();
        $this->assertFalse($e->enforce('alice', 'data1', 'read'));
    }

    public function testSavePolicy()
    {
        $policyFile = __DIR__.'/Persist/Adapters/rbac_policy_test.csv';
        file_put_contents($policyFile, '', LOCK_EX);

        $e = new Enforcer($this->modelAndPolicyPath.'/rbac_model.conf', $policyFile);
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

        $e2 = new Enforcer($this->modelAndPolicyPath.'/rbac_model.conf', $policyFile);
        $this->assertEquals($e2->enforce('alice', 'data1', 'read'), true);
        $this->assertEquals($e2->enforce('bob', 'data2', 'write'), true);
        $this->assertEquals($e2->enforce('alice', 'data2', 'read'), true);
        $this->assertEquals($e2->enforce('alice', 'data2', 'write'), true);
        file_put_contents($policyFile, '', LOCK_EX);
    }

    public function testEnableEnforce()
    {
        $e = new Enforcer($this->modelAndPolicyPath.'/basic_model.conf', $this->modelAndPolicyPath.'/basic_policy.csv');
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
}
