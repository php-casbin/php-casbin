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
    private $modelAndPolicyPath = __DIR__.'/../../../examples';

    public function testGetPolicy()
    {
        $m = new Model();
        $m->loadModel($this->modelAndPolicyPath.'/basic_model.conf');

        $rule = ['admin', 'domain1', 'data1', 'read'];

        $m->addPolicy('p', 'p', $rule);

        $this->assertTrue($m->getPolicy('p', 'p') == [$rule]);
    }

    public function testHasPolicy()
    {
        $m = new Model();
        $m->loadModel($this->modelAndPolicyPath.'/basic_model.conf');

        $rule = ['admin', 'domain1', 'data1', 'read'];

        $m->addPolicy('p', 'p', $rule);

        $this->assertTrue($m->hasPolicy('p', 'p', $rule));
    }

    public function testAddPolicy()
    {
        $m = new Model();
        $m->loadModel($this->modelAndPolicyPath.'/basic_model.conf');

        $rule = ['admin', 'domain1', 'data1', 'read'];

        $this->assertFalse($m->hasPolicy('p', 'p', $rule));
        $m->addPolicy('p', 'p', $rule);

        $this->assertTrue($m->hasPolicy('p', 'p', $rule));
    }

    public function testRemovePolicy()
    {
        $m = new Model();
        $m->loadModel($this->modelAndPolicyPath.'/basic_model.conf');

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
        $m->loadModel($this->modelAndPolicyPath.'/rbac_with_domains_model.conf');

        $rule = ['admin', 'domain1', 'data1', 'read'];

        $m->addPolicy('p', 'p', $rule);

        $res = $m->removeFilteredPolicy('p', 'p', 1, 'domain1', 'data1');

        $this->assertTrue($res);

        $res = $m->removeFilteredPolicy('p', 'p', 1, 'domain1', 'read');

        $this->assertFalse($res);
    }

    public function testGetValuesForFieldInPolicy()
    {
        $m = new Model();
        $m->loadModel($this->modelAndPolicyPath.'/rbac_with_domains_model.conf');

        $rule = ['admin', 'domain1', 'data1', 'read'];

        $m->addPolicy('p', 'p', $rule);

        $res = $m->getValuesForFieldInPolicy('p', 'p', 1);

        $this->assertTrue(['domain1'] == $res);
    }
}
