<?php

declare(strict_types=1);

namespace Casbin\Model;

use Casbin\Exceptions\CasbinException;
use Casbin\Rbac\RoleManager;
use Casbin\Log\Log;

/**
 * Class Assertion
 * represents an expression in a section of the model.
 *
 * @author techlee@qq.com
 */
class Assertion
{
    /**
     * $key.
     *
     * @var string
     */
    public $key = '';

    /**
     * $value.
     *
     * @var string
     */
    public $value = '';

    /**
     * $tokens.
     *
     * @var string[]
     */
    public $tokens = [];

    /**
     * $policy.
     *
     * @var string[][]
     */
    public $policy = [];

    /**
     * $policyMap
     *
     * @var array<string, int>
     */
    public $policyMap = [];

    /**
     * $rm.
     *
     * @var RoleManager
     */
    public $rm;

    /**
     * @param RoleManager $rm
     *
     * @throws CasbinException
     */
    public function buildRoleLinks(RoleManager $rm): void
    {
        $this->rm = $rm;
        $count = substr_count($this->value, '_');

        foreach ($this->policy as $rule) {
            if ($count < 2) {
                throw new CasbinException('the number of "_" in role definition should be at least 2');
            }
            if (\count($rule) < $count) {
                throw new CasbinException('grouping policy elements do not meet role definition');
            }

            if (2 == $count) {
                $this->rm->addLink($rule[0], $rule[1]);
            } elseif (3 == $count) {
                $this->rm->addLink($rule[0], $rule[1], $rule[2]);
            } elseif (4 == $count) {
                $this->rm->addLink($rule[0], $rule[1], $rule[2], $rule[3]);
            }
        }

        Log::logPrint('Role links for: ' . $this->key);
        $this->rm->printRoles();
    }
}
