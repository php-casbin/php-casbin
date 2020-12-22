<?php

namespace Casbin\Tests\Unit\Model;

use Casbin\Enforcer;
use Casbin\Exceptions\EvalFunctionException;
use Casbin\Model\Model;
use Casbin\Rbac\DefaultRoleManager\RoleManager;
use Casbin\Util\BuiltinOperations;
use PHPUnit\Framework\TestCase;

/**
 * ModelTest.
 *
 * @author techlee@qq.com
 */
class ModelTest extends TestCase
{
    private $modelAndPolicyPath = __DIR__ . '/../../../examples';

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
        $e = new Enforcer($this->modelAndPolicyPath . '/abac_rule_model.conf', $this->modelAndPolicyPath . '/abac_rule_policy.csv');

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

    public function testEvalFunctionException()
    {
        $this->expectException(EvalFunctionException::class);
        $this->expectExceptionMessage("please make sure rule exists in policy when using eval() in matcher");

        $e = new Enforcer($this->modelAndPolicyPath . '/abac_rule_model.conf', "");

        $sub1 = new User('alice', 18);

        $e->enforce($sub1, '/data1', 'read');
    }

    public function testRBACModelWithPattern()
    {


        $e = new Enforcer($this->modelAndPolicyPath . '/rbac_with_pattern_model.conf', $this->modelAndPolicyPath . '/rbac_with_pattern_policy.csv');


        $e->getRoleManager() instanceof RoleManager;

        $e->getRoleManager()->addMatchingFunc('keyMatch2', function (string $key1, string $key2) {
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

        $e->getRoleManager()->addMatchingFunc('keyMatch3', function (string $key1, string $key2) {
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

    public function testDomainMatchModel()
    {
        $e = new Enforcer($this->modelAndPolicyPath . '/rbac_with_domain_pattern_model.conf', $this->modelAndPolicyPath . '/rbac_with_domain_pattern_policy.csv');
        $e->getRoleManager()->addDomainMatchingFunc('keyMatch2', function (string $key1, string $key2) {
            return BuiltinOperations::keyMatch2($key1, $key2);
        });

        $this->assertEquals($e->enforce('alice', 'domain1', 'data1', 'read'), true);
        $this->assertEquals($e->enforce('alice', 'domain1', 'data1', 'write'), true);
        $this->assertEquals($e->enforce('alice', 'domain1', 'data2', 'read'), false);
        $this->assertEquals($e->enforce('alice', 'domain1', 'data2', 'write'), false);
        $this->assertEquals($e->enforce('alice', 'domain2', 'data2', 'read'), true);
        $this->assertEquals($e->enforce('alice', 'domain2', 'data2', 'write'), true);
        $this->assertEquals($e->enforce('bob', 'domain2', 'data1', 'read'), false);
        $this->assertEquals($e->enforce('bob', 'domain2', 'data1', 'write'), false);
        $this->assertEquals($e->enforce('bob', 'domain2', 'data2', 'read'), true);
        $this->assertEquals($e->enforce('bob', 'domain2', 'data2', 'write'), true);
    }

    public function testAllMatchModel()
    {
        $e = new Enforcer($this->modelAndPolicyPath . '/rbac_with_all_pattern_model.conf', $this->modelAndPolicyPath . '/rbac_with_all_pattern_policy.csv');
        $e->getRoleManager()->addMatchingFunc('keyMatch2', function (string $key1, string $key2) {
            return BuiltinOperations::keyMatch2($key1, $key2);
        });
        $e->getRoleManager()->addDomainMatchingFunc('keyMatch2', function (string $key1, string $key2) {
            return BuiltinOperations::keyMatch2($key1, $key2);
        });

        $this->assertEquals($e->enforce('alice', 'domain1', '/book/1', 'read'), true);
        $this->assertEquals($e->enforce('alice', 'domain1', '/book/1', 'write'), false);
        $this->assertEquals($e->enforce('alice', 'domain2', '/book/1', 'read'), false);
        $this->assertEquals($e->enforce('alice', 'domain2', '/book/1', 'write'), true);
    }
}
