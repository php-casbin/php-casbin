<?php

namespace Casbin\Tests\Unit;

use Casbin\Enforcer;
use Casbin\Util\BuiltinOperations;
use PHPUnit\Framework\TestCase;

/**
 * ModelBenchmarkTest .
 *
 * @author techlee@qq.com
 */
class ModelBenchmarkTest extends TestCase
{
    private $modelAndPolicyPath = __DIR__ . '/../../examples';

    public function testRawEnforce(): void
    {
        $rawEnforce = function (string $sub, string $obj, string $act) {
            $policy = [["alice", "data1", "read"], ["bob", "data2", "write"]];
            foreach ($policy as $rule) {
                if ($sub == $rule[0] && $obj == $rule[1] && $act == $rule[2]) {
                    return true;
                }
            }
            return false;
        };

        $this->benchmark(function () use ($rawEnforce) {
            $rawEnforce("alice", "data1", "read");
        }, 10000);
    }

    public function testBaseModel(): void
    {
        $e = new Enforcer($this->modelAndPolicyPath . '/basic_model.conf', $this->modelAndPolicyPath . "/basic_policy.csv", false);
        $this->benchmark(function () use ($e) {
            $e->enforce("alice", "data1", "read");
        }, 10000);
    }

    public function testRBACModel(): void
    {
        $e = new Enforcer($this->modelAndPolicyPath . '/rbac_model.conf', $this->modelAndPolicyPath . "/rbac_model.csv", false);
        $this->benchmark(function () use ($e) {
            $e->enforce("alice", "data2", "read");
        }, 10000);
    }

    public function testRBACModelSmall(): void
    {
        $e = new Enforcer($this->modelAndPolicyPath . "/rbac_model.conf", false);

        // 100 roles, 10 resources.
        for ($i = 0; $i < 100; $i++) {
            $e->addPolicy(sprintf("group%d", $i), sprintf("data%d", $i / 10), "read");
        }

        // 1000 users.
        for ($i = 0; $i < 1000; $i++) {
            $e->addGroupingPolicy(sprintf("user%d", $i), sprintf("group%d", $i / 10));
        }
        $this->benchmark(function () use ($e) {
            $e->enforce("user501", "data9", "read");
        }, 1000);
    }

    public function testRBACModelMedium(): void
    {
        $e = new Enforcer($this->modelAndPolicyPath . "/rbac_model.conf", false);

        // 1000 roles, 100 resources.
        $pPolicies = [];
        for ($i = 0; $i < 1000; $i++) {
            $pPolicies[] = [sprintf("group%d", $i), sprintf("data%d", $i / 10), "read"];
        }

        $e->addPolicies($pPolicies);

        // 10000 users.
        $gPolicies = [];
        for ($i = 0; $i < 10000; $i++) {
            $gPolicies[] = [sprintf("user%d", $i), sprintf("group%d", $i / 10)];
        }

        $e->addGroupingPolicies($gPolicies);

        $this->benchmark(function () use ($e) {
            $e->enforce("user5001", "data99", "read");
        }, 100);
    }

    public function testRBACModelLarge(): void
    {
        $e = new Enforcer($this->modelAndPolicyPath . "/rbac_model.conf", false);

        // 10000 roles, 1000 resources.
        $pPolicies = [];
        for ($i = 0; $i < 10000; $i++) {
            $pPolicies[] = [sprintf("group%d", $i), sprintf("data%d", $i / 10), "read"];
        }

        $e->addPolicies($pPolicies);

        // 100000 users.
        $gPolicies = [];
        for ($i = 0; $i < 100000; $i++) {
            $gPolicies[] = [sprintf("user%d", $i), sprintf("group%d", $i / 10)];
        }

        $e->addGroupingPolicies($gPolicies);

        $this->benchmark(function () use ($e) {
            $e->enforce("user50001", "data999", "read");
        }, 10);
    }


    public function testRBACModelWithResourceRoles(): void
    {
        $e = new Enforcer($this->modelAndPolicyPath . "/rbac_with_resource_roles_model.conf", $this->modelAndPolicyPath . "/rbac_with_resource_roles_policy.csv", false);


        $this->benchmark(function () use ($e) {
            $e->enforce("alice", "data1", "read");
        }, 1000);
    }

    public function testRBACModelWithDomains(): void
    {
        $e = new Enforcer($this->modelAndPolicyPath . "/rbac_with_domains_model.conf", $this->modelAndPolicyPath . "/rbac_with_domains_policy.csv", false);


        $this->benchmark(function () use ($e) {
            $e->enforce("alice", "domain1", "data1", "read");
        }, 1000);
    }

    public function testABACModel(): void
    {
        $e = new Enforcer($this->modelAndPolicyPath . "/abac_model.conf", false);
        $data1 = new \stdClass();
        $data1->Name = "data1";
        $data1->Owner = "alice";

        $this->benchmark(function () use ($e, $data1) {
            $e->enforce("alice", $data1, "read");
        }, 1000);
    }

    public function testKeyMatchModel(): void
    {
        $e = new Enforcer($this->modelAndPolicyPath . "/keymatch_model.conf", $this->modelAndPolicyPath . "/keymatch_policy.csv", false);


        $this->benchmark(function () use ($e) {
            $e->enforce("alice", "/alice_data/resource1", "GET");
        }, 1000);
    }

    public function testRBACModelWithDeny(): void
    {
        $e = new Enforcer($this->modelAndPolicyPath . "/rbac_with_deny_model.conf", $this->modelAndPolicyPath . "/rbac_with_deny_policy.csv");


        $this->benchmark(function () use ($e) {
            $e->enforce("alice", "data1", "read");
        }, 1000);
    }

    public function testPriorityModel(): void
    {
        $e = new Enforcer($this->modelAndPolicyPath . "/priority_model.conf", $this->modelAndPolicyPath . "/priority_policy.csv");

        $this->benchmark(function () use ($e) {
            $e->enforce("alice", "data1", "read");
        }, 1000);
    }

    public function testRBACModelWithDomainPatternLarge(): void
    {
        $e = new Enforcer($this->modelAndPolicyPath . "/performance/rbac_with_pattern_large_scale_model.conf", $this->modelAndPolicyPath . "/performance/rbac_with_pattern_large_scale_policy.csv");
        $e->addNamedDomainMatchingFunc("g", "keyMatch4", function (...$args) {
            return BuiltinOperations::keyMatch4Func(...$args);
        });
        $e->buildRoleLinks();

        $this->benchmark(function () use ($e) {
            $e->enforce("staffUser1001", "/orgs/1/sites/site001", "App001.Module001.Action1001");
        }, 1000);
    }

    protected function benchmark(\Closure $closure, int $n = 100): void
    {
        $x = microtime(true);
        for ($i = 0; $i < $n; $i++) {
            $closure();
        }
        $x = microtime(true) - $x;
        $fn = isset(debug_backtrace()[1]['function']) ? debug_backtrace()[1]['function'] : __FUNCTION__;
        printf(
            "%s %s %s ms/op". PHP_EOL,
            str_pad($fn, 45, " ", STR_PAD_RIGHT),
            str_pad(strval($n), 8, " ", STR_PAD_LEFT),
            str_pad(sprintf("%.6f", $x * 1000 / $n), 12, " ", STR_PAD_LEFT)
        );
        $this->assertTrue(true);
    }
}
