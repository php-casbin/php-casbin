<?php

namespace Casbin\Tests\Unit\Model;

use Casbin\Enforcer;
use Casbin\Model\Model;
use PHPUnit\Framework\TestCase;

/**
 * ModelTest.
 *
 * @author techlee@qq.com
 */
class ModelTest extends TestCase
{
    private $modelAndPolicyPath = __DIR__.'/../../../examples';

    public function testLoadModelFromText()
    {
        $text = <<<'EOT'
# Request definition
[request_definition]
r = sub, obj, act

# Policy definition
[policy_definition]
p = sub, obj, act

# Policy effect
[policy_effect]
e = some(where (p.eft == allow))

# Matchers
[matchers]
m = r.sub == p.sub && r.obj == p.obj && r.act == p.act
EOT;
        $m = new Model();
        $m->loadModelFromText($text);

        $rule = ['alice', 'data1', 'read'];
        $m->addPolicy('p', 'p', $rule);
        $rule = ['bob', 'data2', 'write'];
        $m->addPolicy('p', 'p', $rule);

        $e = new Enforcer($m);

        $this->assertTrue($e->enforce('alice', 'data1', 'read'));
        $this->assertFalse($e->enforce('alice', 'data2', 'write'));
        $this->assertFalse($e->enforce('bob', 'data1', 'read'));
        $this->assertTrue($e->enforce('bob', 'data2', 'write'));
    }

    public function testABACPolicy()
    {
        $e = new Enforcer($this->modelAndPolicyPath.'/abac_rule_model.conf', $this->modelAndPolicyPath.'/abac_rule_policy.csv');

        $sub1 = new User('alice', 18);
        $sub2 = new User('alice', 20);
        $sub3 = new User('alice', 65);

        $this->assertEquals($e->enforce($sub1, '/data1', 'read'), false);
        $this->assertEquals($e->enforce($sub1, '/data2', 'read'), false);
        $this->assertEquals($e->enforce($sub1, '/data1', 'write'), false);
        $this->assertEquals($e->enforce($sub1, '/data2', 'write'), true);
        $this->assertEquals($e->enforce($sub2, '/data1', 'read'), true);
        $this->assertEquals($e->enforce($sub2, '/data2', 'read'), false);
        $this->assertEquals($e->enforce($sub2, '/data1', 'write'), false);
        $this->assertEquals($e->enforce($sub2, '/data2', 'write'), true);
        $this->assertEquals($e->enforce($sub3, '/data1', 'read'), true);
        $this->assertEquals($e->enforce($sub3, '/data2', 'read'), false);
        $this->assertEquals($e->enforce($sub3, '/data1', 'write'), false);
        $this->assertEquals($e->enforce($sub3, '/data2', 'write'), false);
    }
}
