<?php

declare(strict_types=1);

namespace Casbin\Model;

use Casbin\Exceptions\CasbinException;
use Casbin\Log\Logger;
use Casbin\Rbac\ConditionalRoleManager;
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
     * $paramsTokens.
     *
     * @var string[]
     */
    public array $paramsTokens = [];

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
     * $condRmMap
     *
     * @var ConditionalRoleManager|null
     */
    public ?ConditionalRoleManager $condRm = null;

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
            if (count($rule) < $count) {
                throw new CasbinException('grouping policy elements do not meet role definition');
            }
            if (count($rule) > $count) {
                $rule = array_slice($rule, 0, $count);
            }

            $this->rm->addLink($rule[0], $rule[1], ...array_slice($rule, 2));
        }
    }

    /**
     * @param RoleManager $rm
     * @param integer $op
     * @param string[][] $rules
     * 
     * @return void
     * 
     * @throws CasbinException
     */
    public function buildIncrementalRoleLinks(RoleManager $rm, int $op, array $rules): void
    {
        $this->rm = $rm;
        $count = substr_count($this->value, '_');
        if ($count < 2) {
            throw new CasbinException('the number of "_" in role definition should be at least 2');
        }

        foreach ($rules as $rule) {
            if (count($rule) < $count) {
                throw new CasbinException('grouping policy elements do not meet role definition');
            }
            if (count($rule) > $count) {
                $rule = array_slice($rule, 0, $count);
            }
            match ($op) {
                Policy::POLICY_ADD => $this->rm->addLink($rule[0], $rule[1], ...array_slice($rule, 2)),
                Policy::POLICY_REMOVE => $this->rm->deleteLink($rule[0], $rule[1], ...array_slice($rule, 2)),
                default => throw new CasbinException('invalid policy operation')
            };
        }
    }

    /**
     * @param ConditionalRoleManager $condRm
     * 
     * @return void
     *
     * @throws CasbinException
     */
    public function buildConditionalRoleLinks(ConditionalRoleManager $condRm): void
    {
        $this->condRm = $condRm;
        $count = substr_count($this->value, '_');
        if ($count < 2) {
            throw new CasbinException('the number of "_" in role definition should be at least 2');
        }

        foreach ($this->policy as $rule) {
            if (count($rule) < $count) {
                throw new CasbinException('grouping policy elements do not meet role definition');
            }
            if (count($rule) > $count) {
                $rule = array_slice($rule, 0, $count);
            }

            $domainRule = array_slice($rule, 2, count($this->tokens) - 2);

            $this->addConditionalRoleLink($rule, $domainRule);
        }
    }

    /**
     * @param ConditionalRoleManager $condRm
     * @param integer $op
     * @param string[][] $rules
     * 
     * @return void
     * 
     * @throws CasbinException
     */
    public function buildIncrementalConditionalRoleLinks(ConditionalRoleManager $condRm, int $op, array $rules): void
    {
        $this->condRm = $condRm;
        $count = substr_count($this->value, '_');
        if ($count < 2) {
            throw new CasbinException('the number of "_" in role definition should be at least 2');
        }

        foreach ($rules as $rule) {
            if (count($rule) < $count) {
                throw new CasbinException('grouping policy elements do not meet role definition');
            }
            if (count($rule) > $count) {
                $rule = array_slice($rule, 0, $count);
            }

            $domainRule = array_slice($rule, 2, count($this->tokens) - 2);

            match ($op) {
                Policy::POLICY_ADD => $this->addConditionalRoleLink($rule, $domainRule),
                Policy::POLICY_REMOVE => $this->condRm->deleteLink($rule[0], $rule[1], ...array_slice($rule, 2)),
                default => throw new CasbinException('invalid policy operation')
            };
        }
    }

    /**
     * @param array $rule
     * @param array $domainRule
     * 
     * @return void
     */
    public function addConditionalRoleLink(array $rule, array $domainRule): void
    {
        if (count($domainRule) === 0) {
            $this->condRm->addLink($rule[0], $rule[1]);
            $this->condRm->setLinkConditionFuncParams($rule[0], $rule[1], ...array_slice($rule, count($this->tokens)));
        } else {
            $domain = $domainRule[0];
            $this->condRm->addLink($rule[0], $rule[1], $domain);
            $this->condRm->setDomainLinkConditionFuncParams($rule[0], $rule[1], $domain, ...array_slice($rule, count($this->tokens)));
        }
    }
}
