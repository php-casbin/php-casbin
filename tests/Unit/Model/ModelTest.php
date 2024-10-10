<?php

namespace Casbin\Tests\Unit\Model;

use Casbin\Enforcer;
use Casbin\Exceptions\EvalFunctionException;
use Casbin\Model\Model;
use Casbin\Util\BuiltinOperations;
use Casbin\Util\Util;
use PHPUnit\Framework\TestCase;
use stdClass;

/**
 * ModelTest.
 *
 * @author techlee@qq.com
 */
class ModelTest extends TestCase
{
    private $modelAndPolicyPath = __DIR__ . '/../../../examples';

    public static function newTestResource(string $name, string $owner): stdClass
    {
        $r = new stdClass();
        $r->name = $name;
        $r->owner = $owner;
        return $r;
    }

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

    public function testABACNotUsingPolicy()
    {
        $e = new Enforcer($this->modelAndPolicyPath . '/abac_not_using_policy_model.conf', $this->modelAndPolicyPath . '/abac_rule_effect_policy.csv');
        $data1 = self::newTestResource('data1', 'alice');
        $data2 = self::newTestResource('data2', 'bob');

        $this->assertEquals($e->enforce('alice', $data1, 'read'), true);
        $this->assertEquals($e->enforce('alice', $data1, 'write'), true);
        $this->assertEquals($e->enforce('alice', $data2, 'read'), false);
        $this->assertEquals($e->enforce('alice', $data2, 'write'), false);
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

        // Here's a little confusing: the matching function here is not the custom function used in matcher.
        // It is the matching function used by "g" (and "g2", "g3" if any..)
        // You can see in policy that: "g2, /book/:id, book_group", so in "g2()" function in the matcher, instead
        // of checking whether "/book/:id" equals the obj: "/book/1", it checks whether the pattern matches.
        // You can see it as normal RBAC: "/book/:id" == "/book/1" becomes KeyMatch2("/book/:id", "/book/1")
        $e->addNamedMatchingFunc('g2', 'keyMatch2', fn(string $key1, string $key2) => BuiltinOperations::keyMatch2($key1, $key2));
        $this->assertEquals($e->enforce('alice', '/book/1', 'GET'), true);
        $this->assertEquals($e->enforce('alice', '/book/2', 'GET'), true);
        $this->assertEquals($e->enforce('alice', '/pen/1', 'GET'), true);
        $this->assertEquals($e->enforce('alice', '/pen/2', 'GET'), false);
        $this->assertEquals($e->enforce('bob', '/book/1', 'GET'), false);
        $this->assertEquals($e->enforce('bob', '/book/2', 'GET'), false);
        $this->assertEquals($e->enforce('bob', '/pen/1', 'GET'), true);
        $this->assertEquals($e->enforce('bob', '/pen/2', 'GET'), true);

        // AddMatchingFunc() is actually setting a function because only one function is allowed,
        // so when we set "KeyMatch3", we are actually replacing "KeyMatch2" with "KeyMatch3".
        $e->addNamedMatchingFunc('g2', 'keyMatch2', fn (string $key1, string $key2) => BuiltinOperations::keyMatch3($key1, $key2));
        $this->assertEquals($e->enforce('alice', '/book2/1', 'GET'), true);
        $this->assertEquals($e->enforce('alice', '/book2/2', 'GET'), true);
        $this->assertEquals($e->enforce('alice', '/pen2/1', 'GET'), true);
        $this->assertEquals($e->enforce('alice', '/pen2/2', 'GET'), false);
        $this->assertEquals($e->enforce('bob', '/book2/1', 'GET'), false);
        $this->assertEquals($e->enforce('bob', '/book2/2', 'GET'), false);
        $this->assertEquals($e->enforce('bob', '/pen2/1', 'GET'), true);
        $this->assertEquals($e->enforce('bob', '/pen2/2', 'GET'), true);
    }

    public function testRBACModelWithDifferentTypesOfRoles()
    {
        $e = new Enforcer($this->modelAndPolicyPath . '/rbac_with_different_types_of_roles_model.conf', $this->modelAndPolicyPath . '/rbac_with_different_types_of_roles_policy.csv');

        $g = $e->getNamedGroupingPolicy('g');
        foreach ($g as $gp) {
            if (count($gp) !== 5) {
                $this->fail("g parameters' num isn't 5");
                return;
            }
            $e->addNamedDomainLinkConditionFunc('g', $gp[0], $gp[1], $gp[2], fn ($key1, $key2) => BuiltinOperations::timeMatch($key1, $key2));
        }
        $this->assertEquals($e->enforce('alice', 'data1', 'read'), true);
        $this->assertEquals($e->enforce('alice', 'data1', 'write'), true);
        $this->assertEquals($e->enforce('alice', 'data2', 'read'), false);
        $this->assertEquals($e->enforce('alice', 'data2', 'write'), false);
        $this->assertEquals($e->enforce('bob', 'data1', 'read'), false);
        $this->assertEquals($e->enforce('bob', 'data1', 'write'), false);
        $this->assertEquals($e->enforce('bob', 'data2', 'read'), true);
        $this->assertEquals($e->enforce('bob', 'data2', 'write'), false);
        $this->assertEquals($e->enforce('carol', 'data1', 'read'), false);
        $this->assertEquals($e->enforce('carol', 'data1', 'write'), false);
        $this->assertEquals($e->enforce('carol', 'data2', 'read'), false);
        $this->assertEquals($e->enforce('carol', 'data2', 'write'), false);
    }

    public function testDomainMatchModel()
    {
        $e = new Enforcer($this->modelAndPolicyPath . '/rbac_with_domain_pattern_model.conf', $this->modelAndPolicyPath . '/rbac_with_domain_pattern_policy.csv');
        $e->addNamedDomainMatchingFunc('g', 'keyMatch2', fn(string $key1, string $key2) => BuiltinOperations::keyMatch2($key1, $key2));

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
        $e->addNamedMatchingFunc('g', 'keyMatch2', fn(string $key1, string $key2) => BuiltinOperations::keyMatch2($key1, $key2));
        $e->addNamedDomainMatchingFunc('g', 'keyMatch2', fn(string $key1, string $key2) => BuiltinOperations::keyMatch2($key1, $key2));

        $this->assertEquals($e->enforce('alice', 'domain1', '/book/1', 'read'), true);
        $this->assertEquals($e->enforce('alice', 'domain1', '/book/1', 'write'), false);
        $this->assertEquals($e->enforce('alice', 'domain2', '/book/1', 'read'), false);
        $this->assertEquals($e->enforce('alice', 'domain2', '/book/1', 'write'), true);
    }

    public function testTemporalRolesModel()
    {
        $e = new Enforcer($this->modelAndPolicyPath . '/rbac_with_temporal_roles_model.conf', $this->modelAndPolicyPath . '/rbac_with_temporal_roles_policy.csv');
        $fn = fn(string $key1, string $key2) => BuiltinOperations::timeMatch($key1, $key2);
        $e->addNamedLinkConditionFunc('g', 'alice', 'data2_admin', $fn);
        $e->addNamedLinkConditionFunc('g', 'alice', 'data3_admin', $fn);
        $e->addNamedLinkConditionFunc('g', 'alice', 'data4_admin', $fn);
        $e->addNamedLinkConditionFunc('g', 'alice', 'data5_admin', $fn);
        $e->addNamedLinkConditionFunc('g', 'alice', 'data6_admin', $fn);
        $e->addNamedLinkConditionFunc('g', 'alice', 'data7_admin', $fn);
        $e->addNamedLinkConditionFunc('g', 'alice', 'data8_admin', $fn);

        $this->assertEquals($e->enforce('alice', 'data1', 'read'), true);
        $this->assertEquals($e->enforce('alice', 'data1', 'write'), true);
        $this->assertEquals($e->enforce('alice', 'data2', 'read'), false);
        $this->assertEquals($e->enforce('alice', 'data2', 'write'), false);
        $this->assertEquals($e->enforce('alice', 'data3', 'read'), true);
        $this->assertEquals($e->enforce('alice', 'data3', 'write'), true);
        $this->assertEquals($e->enforce('alice', 'data4', 'read'), true);
        $this->assertEquals($e->enforce('alice', 'data4', 'write'), true);
        $this->assertEquals($e->enforce('alice', 'data5', 'read'), true);
        $this->assertEquals($e->enforce('alice', 'data5', 'write'), true);
        $this->assertEquals($e->enforce('alice', 'data6', 'read'), false);
        $this->assertEquals($e->enforce('alice', 'data6', 'write'), false);
        $this->assertEquals($e->enforce('alice', 'data7', 'read'), true);
        $this->assertEquals($e->enforce('alice', 'data7', 'write'), true);
        $this->assertEquals($e->enforce('alice', 'data8', 'read'), false);
        $this->assertEquals($e->enforce('alice', 'data8', 'write'), false);
    }

    public function testTemporalRolesModelWithDomain()
    {
        $e = new Enforcer($this->modelAndPolicyPath . '/rbac_with_domain_temporal_roles_model.conf', $this->modelAndPolicyPath . '/rbac_with_domain_temporal_roles_policy.csv');
        $fn = fn(string $key1, string $key2) => BuiltinOperations::timeMatch($key1, $key2);
        $e->addNamedDomainLinkConditionFunc('g', 'alice', 'data2_admin', 'domain2', $fn);
        $e->addNamedDomainLinkConditionFunc('g', 'alice', 'data3_admin', 'domain3', $fn);
        $e->addNamedDomainLinkConditionFunc('g', 'alice', 'data4_admin', 'domain4', $fn);
        $e->addNamedDomainLinkConditionFunc('g', 'alice', 'data5_admin', 'domain5', $fn);
        $e->addNamedDomainLinkConditionFunc('g', 'alice', 'data6_admin', 'domain6', $fn);
        $e->addNamedDomainLinkConditionFunc('g', 'alice', 'data7_admin', 'domain7', $fn);
        $e->addNamedDomainLinkConditionFunc('g', 'alice', 'data8_admin', 'domain8', $fn);

        $this->assertEquals($e->enforce('alice', 'domain1', 'data1', 'read'), true);
        $this->assertEquals($e->enforce('alice', 'domain1', 'data1', 'write'), true);
        $this->assertEquals($e->enforce('alice', 'domain2', 'data2', 'read'), false);
        $this->assertEquals($e->enforce('alice', 'domain2', 'data2', 'write'), false);
        $this->assertEquals($e->enforce('alice', 'domain3', 'data3', 'read'), true);
        $this->assertEquals($e->enforce('alice', 'domain3', 'data3', 'write'), true);
        $this->assertEquals($e->enforce('alice', 'domain4', 'data4', 'read'), true);
        $this->assertEquals($e->enforce('alice', 'domain4', 'data4', 'write'), true);
        $this->assertEquals($e->enforce('alice', 'domain5', 'data5', 'read'), true);
        $this->assertEquals($e->enforce('alice', 'domain5', 'data5', 'write'), true);
        $this->assertEquals($e->enforce('alice', 'domain6', 'data6', 'read'), false);
        $this->assertEquals($e->enforce('alice', 'domain6', 'data6', 'write'), false);
        $this->assertEquals($e->enforce('alice', 'domain7', 'data7', 'read'), true);
        $this->assertEquals($e->enforce('alice', 'domain7', 'data7', 'write'), true);
        $this->assertEquals($e->enforce('alice', 'domain8', 'data8', 'read'), false);
        $this->assertEquals($e->enforce('alice', 'domain8', 'data8', 'write'), false);

        $this->assertEquals($e->enforce('alice', 'domain_not_exist', 'data1', 'read'), false);
        $this->assertEquals($e->enforce('alice', 'domain_not_exist', 'data1', 'write'), false);
        $this->assertEquals($e->enforce('alice', 'domain_not_exist', 'data2', 'read'), false);
        $this->assertEquals($e->enforce('alice', 'domain_not_exist', 'data2', 'write'), false);
        $this->assertEquals($e->enforce('alice', 'domain_not_exist', 'data3', 'read'), false);
        $this->assertEquals($e->enforce('alice', 'domain_not_exist', 'data3', 'write'), false);
        $this->assertEquals($e->enforce('alice', 'domain_not_exist', 'data4', 'read'), false);
        $this->assertEquals($e->enforce('alice', 'domain_not_exist', 'data4', 'write'), false);
        $this->assertEquals($e->enforce('alice', 'domain_not_exist', 'data5', 'read'), false);
        $this->assertEquals($e->enforce('alice', 'domain_not_exist', 'data5', 'write'), false);
        $this->assertEquals($e->enforce('alice', 'domain_not_exist', 'data6', 'read'), false);
        $this->assertEquals($e->enforce('alice', 'domain_not_exist', 'data6', 'write'), false);
        $this->assertEquals($e->enforce('alice', 'domain_not_exist', 'data7', 'read'), false);
        $this->assertEquals($e->enforce('alice', 'domain_not_exist', 'data7', 'write'), false);
        $this->assertEquals($e->enforce('alice', 'domain_not_exist', 'data8', 'read'), false);
        $this->assertEquals($e->enforce('alice', 'domain_not_exist', 'data8', 'write'), false);
    }
}
