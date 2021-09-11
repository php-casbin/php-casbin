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
     * $priorityIndex.
     *
     * @var int|bool
     */
    public $priorityIndex;

    public function initPriorityIndex(): void
    {
        $this->priorityIndex = false;
    }

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

    /**
     * @param RoleManager $rm
     * @param integer $op
     * @param string[][] $rules
     * @return void
     */
    public function buildIncrementalRoleLinks(RoleManager $rm, int $op, array $rules): void
    {
        $this->rm = $rm;
        $count = substr_count($this->value, '_');
        if ($count < 2) {
            throw new CasbinException('the number of "_" in role definition should be at least 2');
        }

        foreach ($rules as $rule) {
            if (\count($rule) < $count) {
                throw new CasbinException('grouping policy elements do not meet role definition');
            }
            if (\count($rule) > $count) {
                $rule = array_slice($rule, 0, $count);
            }
            switch ($op) {
                case Policy::POLICY_ADD:
                    $rm->addLink($rule[0], $rule[1], ...array_slice($rule, 2));
                    break;
                case Policy::POLICY_REMOVE:
                    $rm->deleteLink($rule[0], $rule[1], ...array_slice($rule, 2));
                    break;
            }
        }
    }
}
