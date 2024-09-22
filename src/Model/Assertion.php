<?php

declare(strict_types=1);

namespace Casbin\Model;

use Casbin\Exceptions\CasbinException;
use Casbin\Log\Logger;
use Casbin\Rbac\RoleManager;

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
    public string $key = '';

    /**
     * $value.
     *
     * @var string
     */
    public string $value = '';

    /**
     * $tokens.
     *
     * @var string[]
     */
    public array $tokens = [];

    /**
     * $policy.
     *
     * @var string[][]
     */
    public array $policy = [];

    /**
     * $policyMap
     *
     * @var array<string, int>
     */
    public array $policyMap = [];

    /**
     * $rm.
     *
     * @var RoleManager|null
     */
    public ?RoleManager $rm = null;

    /**
     * $fieldIndexMap
     * 
     * @var array<string, int>
     */
    public array $fieldIndexMap = [];

    /**
     * $logger.
     *
     * @var Logger|null
     */
    public ?Logger $logger = null;

    /**
     * Sets the current logger.
     *
     * @param Logger $logger
     * 
     * @return void
     */
    public function setLogger($logger): void
    {
        $this->logger = $logger;
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
        if ($count < 2) {
            throw new CasbinException('the number of "_" in role definition should be at least 2');
        }

        foreach ($this->policy as $rule) {
            if (\count($rule) < $count) {
                throw new CasbinException('grouping policy elements do not meet role definition');
            }
            if (\count($rule) > $count) {
                $rule = \array_slice($rule, 0, $count);
            }

            $this->rm->addLink($rule[0], $rule[1], ...\array_slice($rule, 2));
        }
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
            match ($op) {
                Policy::POLICY_ADD => $this->rm->addLink($rule[0], $rule[1], ...array_slice($rule, 2)),
                Policy::POLICY_REMOVE => $this->rm->deleteLink($rule[0], $rule[1], ...array_slice($rule, 2)),
                default => throw new CasbinException('invalid policy operation')
            };
        }
    }
}
