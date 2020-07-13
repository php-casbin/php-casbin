<?php

namespace Casbin\Tests\Unit\Model;

use Casbin\Enforcer;
use Casbin\Model\Model;
use Casbin\Util\BuiltinOperations;
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

    public function testRBACModelWithPattern()
    {
        $e = new Enforcer($this->modelAndPolicyPath.'/rbac_with_pattern_model.conf', $this->modelAndPolicyPath.'/rbac_with_pattern_policy.csv');

        $e->addMatchingFunc('keyMatch2', function (string $key1, string $key2) {
            return BuiltinOperations::keyMatch2($key1, $key2);
        });
        $this->assertEquals($e->enforce('alice', '/book/1', 'GET'), true);
        $this->assertEquals($e->enforce('alice', '/book/2', 'GET'), true);
        $this->assertEquals($e->enforce('alice', '/pen/1', 'GET'), true);
        $this->assertEquals($e->enforce('alice', '/pen/2', 'GET'), false);
        $this->assertEquals($e->enforce('bob', '/book/1', 'GET'), false);
        $this->assertEquals($e->enforce('bob', '/book/2', 'GET'), false);
        $this->assertEquals($e->enforce('bob', '/pen/1', 'GET'), true);
        $this->assertEquals($e->enforce('bob', '/pen/2', 'GET'), true);

        $e->addMatchingFunc('keyMatch3', function (string $key1, string $key2) {
            return BuiltinOperations::keyMatch3($key1, $key2);
        });
        $this->assertEquals($e->enforce('alice', '/book2/1', 'GET'), true);
        $this->assertEquals($e->enforce('alice', '/book2/2', 'GET'), true);
        $this->assertEquals($e->enforce('alice', '/pen2/1', 'GET'), true);
        $this->assertEquals($e->enforce('alice', '/pen2/2', 'GET'), false);
        $this->assertEquals($e->enforce('bob', '/book2/1', 'GET'), false);
        $this->assertEquals($e->enforce('bob', '/book2/2', 'GET'), false);
        $this->assertEquals($e->enforce('bob', '/pen2/1', 'GET'), true);
        $this->assertEquals($e->enforce('bob', '/pen2/2', 'GET'), true);
    }
}
