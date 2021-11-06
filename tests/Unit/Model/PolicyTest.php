<?php

namespace Casbin\Tests\Unit\Model;

use Casbin\Model\Model;
use PHPUnit\Framework\TestCase;

/**
 * PolicyTest.
 *
 * @author techlee@qq.com
 */
class PolicyTest extends TestCase
{
    private $modelAndPolicyPath = __DIR__ . '/../../../examples';

    public function testGetPolicy()
    {
        $m = new Model();
        $m->loadModel($this->modelAndPolicyPath . '/basic_model.conf');

        $rule = ['admin', 'domain1', 'data1', 'read'];

        $m->addPolicy('p', 'p', $rule);

        $this->assertTrue($m->getPolicy('p', 'p') == [$rule]);
    }

    public function testHasPolicy()
    {
        $m = new Model();
        $m->loadModel($this->modelAndPolicyPath . '/basic_model.conf');

        $rule = ['admin', 'domain1', 'data1', 'read'];

        $m->addPolicy('p', 'p', $rule);

        $this->assertTrue($m->hasPolicy('p', 'p', $rule));
    }

    public function testHasPolicies()
    {
        $m = Model::newModelFromFile($this->modelAndPolicyPath . '/basic_model.conf');
        $rules = [
            ['alice', 'domain1', 'data1', 'read'],
            ['alice', 'domain1', 'data2', 'read'],
            ['bob', 'domain2', 'data1', 'write'],
            ['bob', 'domain2', 'data2', 'write'],
        ];

        $m->addPolicies('p', 'p', $rules);

        $this->assertTrue($m->hasPolicies('p', 'p', [
            ['alice', 'domain1', 'data1', 'read'],
            ['bob', 'domain2', 'data1', 'write'],
        ]));

        $this->assertFalse($m->hasPolicies('p', 'p', [
            ['alice', 'domain1', 'data1', 'write'],
        ]));
    }

    public function testAddPolicy()
    {
        $m = new Model();
        $m->loadModel($this->modelAndPolicyPath . '/basic_model.conf');

        $rule = ['admin', 'domain1', 'data1', 'read'];

        $this->assertFalse($m->hasPolicy('p', 'p', $rule));
        $m->addPolicy('p', 'p', $rule);

        $this->assertTrue($m->hasPolicy('p', 'p', $rule));
    }

    public function testUpdatePolicy()
    {
        $m = Model::newModelFromFile($this->modelAndPolicyPath . '/basic_model.conf');
        $rules = [
            ['alice', 'domain1', 'data1', 'read'],
            ['alice', 'domain1', 'data2', 'read'],
            ['bob', 'domain2', 'data1', 'write'],
            ['bob', 'domain2', 'data2', 'write'],
        ];

        $m->addPolicies('p', 'p', $rules);

        $this->assertEquals($rules, $m->getPolicy('p', 'p'));
        $this->assertFalse($m->hasPolicies('p', 'p', [
            ['alice', 'domain1', 'data1', 'write'],
        ]));

        $m->updatePolicy('p', 'p', ['alice', 'domain1', 'data1', 'read'], ['alice', 'domain1', 'data1', 'write']);

        $this->assertEquals([
            ['alice', 'domain1', 'data1', 'write'],
            ['alice', 'domain1', 'data2', 'read'],
            ['bob', 'domain2', 'data1', 'write'],
            ['bob', 'domain2', 'data2', 'write'],
        ], $m->getPolicy('p', 'p'));
    }

    public function testUpdatePolicies()
    {
        $m = Model::newModelFromFile($this->modelAndPolicyPath . '/basic_model.conf');
        $rules = [
            ['alice', 'domain1', 'data1', 'read'],
            ['alice', 'domain1', 'data2', 'read'],
            ['bob', 'domain2', 'data1', 'write'],
            ['bob', 'domain2', 'data2', 'write'],
        ];

        $m->addPolicies('p', 'p', $rules);

        $this->assertEquals($rules, $m->getPolicy('p', 'p'));
        $this->assertFalse($m->hasPolicies('p', 'p', [
            ['alice', 'domain1', 'data1', 'write'],
        ]));

        $oldRules = [
            ['alice', 'domain1', 'data1', 'read'],
            ['alice', 'domain1', 'data2', 'read']
        ];
        $newRules = [
            ['alice', 'domain1', 'data1', 'write'],
            ['alice', 'domain1', 'data2', 'write']
        ];
        $m->updatePolicies('p', 'p', $oldRules, $newRules);

        $this->assertEquals([
            ['alice', 'domain1', 'data1', 'write'],
            ['alice', 'domain1', 'data2', 'write'],
            ['bob', 'domain2', 'data1', 'write'],
            ['bob', 'domain2', 'data2', 'write'],
        ], $m->getPolicy('p', 'p'));

        // trigger callback of addPolicies
        $oldRules = [
            ['alice', 'domain1', 'data1', 'write'],
            ['alice', 'domain1', 'data2', 'read']
        ];
        $this->assertFalse($m->updatePolicies('p', 'p', $oldRules, $newRules));
    }

    public function testRemovePolicy()
    {
        $m = new Model();
        $m->loadModel($this->modelAndPolicyPath . '/basic_model.conf');

        $rule = ['admin', 'domain1', 'data1', 'read'];

        $m->addPolicy('p', 'p', $rule);

        $this->assertTrue($m->hasPolicy('p', 'p', $rule));

        $m->removePolicy('p', 'p', $rule);

        $this->assertFalse($m->hasPolicy('p', 'p', $rule));

        $this->assertFalse($m->removePolicy('p', 'p', $rule));
    }

    public function testRemoveFilteredPolicy()
    {
        $m = new Model();
        $m->loadModel($this->modelAndPolicyPath . '/rbac_with_domains_model.conf');

        $rule = ['admin', 'domain1', 'data1', 'read'];

        $m->addPolicy('p', 'p', $rule);

        $res = $m->removeFilteredPolicy('p1', 'p1', 1, 'domain1', 'data1');

        $this->assertFalse($res);

        $res = $m->removeFilteredPolicy('p', 'p', 1, 'domain1', 'data1');

        $this->assertNotFalse($res);

        $res = $m->removeFilteredPolicy('p', 'p', 1, 'domain1', 'read');

        $this->assertFalse($res);
    }

    public function testGetValuesForFieldInPolicy()
    {
        $m = new Model();
        $m->loadModel($this->modelAndPolicyPath . '/rbac_with_domains_model.conf');

        $rule = ['admin', 'domain1', 'data1', 'read'];

        $m->addPolicy('p', 'p', $rule);

        $res = $m->getValuesForFieldInPolicy('p', 'p', 1);

        $this->assertTrue(['domain1'] == $res);
    }
}
