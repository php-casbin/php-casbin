<?php

declare(strict_types=1);

namespace Casbin\Model;

use ArrayAccess;
use Casbin\Exceptions\CasbinException;
use Casbin\Log\Log;
use Casbin\Rbac\RoleManager;
use Casbin\Util\Util;

/**
 * Class Policy.
 *
 * @package Casbin\Model
 * @implements ArrayAccess<string, array<string, Assertion>>
 * @author techlee@qq.com
 */
abstract class Policy implements ArrayAccess
{
    public const POLICY_ADD = 0;

    public const POLICY_REMOVE = 1;

    const DEFAULT_SEP = ",";

    /**
     * All of the Model items.
     *
     * @var array<string, array<string, Assertion>>
     */
    protected $items = [];

    /**
     * BuildIncrementalRoleLinks provides incremental build the role inheritance relations.
     *
     * @param RoleManager[] $rmMap
     * @param integer $op
     * @param string $sec
     * @param string $ptype
     * @param string[][] $rules
     * @return void
     */
    public function buildIncrementalRoleLinks(array $rmMap, int $op, string $sec, string $ptype, array $rules): void
    {
        if ($sec == "g") {
            $this->items[$sec][$ptype]->buildIncrementalRoleLinks($rmMap[$ptype], $op, $rules);
        }
    }

    /**
     * Initializes the roles in RBAC.
     *
     * @param RoleManager[] $rmMap
     * @throws CasbinException
     */
    public function buildRoleLinks(array $rmMap): void
    {
        if (!isset($this->items['g'])) {
            return;
        }

        foreach ($this->items['g'] as $ptype => $ast) {
            $rm = $rmMap[$ptype];
            $ast->buildRoleLinks($rm);
        }
    }

    /**
     * Prints the policy to log.
     */
    public function printPolicy(): void
    {
        Log::logPrint('Policy:');

        foreach (['p', 'g'] as $sec) {
            if (!isset($this->items[$sec])) {
                return;
            }
            foreach ($this->items[$sec] as $key => $ast) {
                Log::logPrint($key, ': ', $ast->value, ': ', $ast->policy);
            }
        }
    }

    /**
     * Clears all current policy.
     */
    public function clearPolicy(): void
    {
        foreach (['p', 'g'] as $sec) {
            if (!isset($this->items[$sec])) {
                return;
            }

            foreach ($this->items[$sec] as $key => $ast) {
                $this->items[$sec][$key]->policy = [];
                $this->items[$sec][$key]->policyMap = [];
            }
        }
    }

    /**
     * Gets all rules in a policy.
     *
     * @param string $sec
     * @param string $ptype
     *
     * @return string[][]
     */
    public function getPolicy(string $sec, string $ptype): array
    {
        return $this->items[$sec][$ptype]->policy;
    }

    /**
     * Gets rules based on field filters from a policy.
     *
     * @param string $sec
     * @param string $ptype
     * @param int $fieldIndex
     * @param string ...$fieldValues
     *
     * @return string[][]
     */
    public function getFilteredPolicy(string $sec, string $ptype, int $fieldIndex, string ...$fieldValues): array
    {
        $res = [];

        foreach ($this->items[$sec][$ptype]->policy as $rule) {
            $matched = true;
            foreach ($fieldValues as $i => $fieldValue) {
                if ('' != $fieldValue && $rule[$fieldIndex + intval($i)] != $fieldValue) {
                    $matched = false;

                    break;
                }
            }

            if ($matched) {
                $res[] = $rule;
            }
        }

        return $res;
    }

    /**
     * Determines whether a model has the specified policy rule.
     *
     * @param string $sec
     * @param string $ptype
     * @param string[] $rule
     *
     * @return bool
     */
    public function hasPolicy(string $sec, string $ptype, array $rule): bool
    {
        if (!isset($this->items[$sec][$ptype])) {
            return false;
        }

        return isset($this->items[$sec][$ptype]->policyMap[implode(self::DEFAULT_SEP, $rule)]);
    }

    /**
     * Determines whether a model has any of the specified policies. If one is found we return true.
     *
     * @param string $sec
     * @param string $ptype
     * @param string[][] $rules
     *
     * @return bool
     */
    public function hasPolicies(string $sec, string $ptype, array $rules): bool
    {
        foreach ($rules as $rule) {
            if ($this->hasPolicy($sec, $ptype, $rule)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Adds a policy rule to the model.
     *
     * @param string $sec
     * @param string $ptype
     * @param string[] $rule
     */
    public function addPolicy(string $sec, string $ptype, array $rule): void
    {
        $assertion = &$this->items[$sec][$ptype];
        $assertion->policy[] = $rule;
        $assertion->policyMap[implode(self::DEFAULT_SEP, $rule)] = count($this->items[$sec][$ptype]->policy) - 1;

        if ($sec == 'p' && $assertion->priorityIndex !== false && $assertion->priorityIndex >= 0) {
            $idxInsert = $rule[$assertion->priorityIndex];
            for ($i = count($assertion->policy) - 1; $i > 0; $i--) {
                $idx = $assertion->policy[$i - 1][$assertion->priorityIndex];
                if ($idx > $idxInsert) {
                    $assertion->policy[$i] = $assertion->policy[$i - 1];
                    $assertion->policyMap[implode(self::DEFAULT_SEP, $assertion->policy[$i - 1])]++;
                } else {
                    break;
                }
            }
            $assertion->policy[$i] = $rule;
            $assertion->policyMap[implode(self::DEFAULT_SEP, $rule)] = $i;
        }
    }

    /**
     * Adds a policy rules to the model.
     *
     * @param string $sec
     * @param string $ptype
     * @param string[][] $rules
     */
    public function addPolicies(string $sec, string $ptype, array $rules): void
    {
        foreach ($rules as $rule) {
            $hashKey = implode(self::DEFAULT_SEP, $rule);
            if (isset($this->items[$sec][$ptype]->policyMap[$hashKey])) {
                continue;
            }
            $this->addPolicy($sec, $ptype, $rule);
        }
    }

    /**
     * Updates a policy rule from the model.
     *
     * @param string $sec
     * @param string $ptype
     * @param string[] $oldRule
     * @param string[] $newRule
     *
     * @return bool
     */
    public function updatePolicy(string $sec, string $ptype, array $oldRule, array $newRule): bool
    {
        $oldPolicy = implode(self::DEFAULT_SEP, $oldRule);
        if (!isset($this->items[$sec][$ptype]->policyMap[$oldPolicy])) {
            return false;
        }

        $index = $this->items[$sec][$ptype]->policyMap[$oldPolicy];
        $this->items[$sec][$ptype]->policy[$index] = $newRule;
        unset($this->items[$sec][$ptype]->policyMap[$oldPolicy]);
        $this->items[$sec][$ptype]->policyMap[implode(self::DEFAULT_SEP, $newRule)] = $index;

        return true;
    }

    /**
     * UpdatePolicies updates a policy rule from the model.
     *
     * @param string $sec
     * @param string $ptype
     * @param string[][] $oldRules
     * @param string[][] $newRules
     * @return boolean
     */
    public function updatePolicies(string $sec, string $ptype, array $oldRules, array $newRules): bool
    {
        $modifiedRuleIndex = [];

        $newIndex = 0;
        foreach ($oldRules as $oldIndex => $oldRule) {
            $oldPolicy = implode(self::DEFAULT_SEP, $oldRule);
            $index = $this->items[$sec][$ptype]->policyMap[$oldPolicy] ?? null;
            if (is_null($index)) {
                // rollback
                foreach ($modifiedRuleIndex as $index => $oldNewIndex) {
                    $this->items[$sec][$ptype]->policy[$index] = $oldRules[$oldNewIndex[0]];
                    $oldPolicy = implode(self::DEFAULT_SEP, $oldRules[$oldNewIndex[0]]);
                    $newPolicy = implode(self::DEFAULT_SEP, $newRules[$oldNewIndex[1]]);
                    unset($this->items[$sec][$ptype]->policyMap[$newPolicy]);
                    $this->items[$sec][$ptype]->policyMap[$oldPolicy] = $index;
                }
                return false;
            }

            $this->items[$sec][$ptype]->policy[$index] = $newRules[$newIndex];
            unset($this->items[$sec][$ptype]->policyMap[$oldPolicy]);
            $this->items[$sec][$ptype]->policyMap[implode(self::DEFAULT_SEP, $newRules[$newIndex])] = $index;
            $modifiedRuleIndex[$index] = [$oldIndex, $newIndex];
            $newIndex++;
        }

        return true;
    }

    /**
     * Removes a policy rule from the model.
     *
     * @param string $sec
     * @param string $ptype
     * @param array $rule
     *
     * @return bool
     */
    public function removePolicy(string $sec, string $ptype, array $rule): bool
    {
        if (!isset($this->items[$sec][$ptype])) {
            return false;
        }

        $hashKey = implode(self::DEFAULT_SEP, $rule);
        if (!isset($this->items[$sec][$ptype]->policyMap[$hashKey])) {
            return false;
        }

        $index = $this->items[$sec][$ptype]->policyMap[$hashKey];
        array_splice($this->items[$sec][$ptype]->policy, $index, 1);

        unset($this->items[$sec][$ptype]->policyMap[$hashKey]);

        $count = count($this->items[$sec][$ptype]->policy);
        for ($i = $index; $i < $count; $i++) {
            $this->items[$sec][$ptype]->policyMap[implode(self::DEFAULT_SEP, $this->items[$sec][$ptype]->policy[$i])] = $i;
        }

        return true;
    }

    /**
     * Removes a policy rules from the model.
     *
     * @param string $sec
     * @param string $ptype
     * @param string[][] $rules
     *
     * @return bool
     */
    public function removePolicies(string $sec, string $ptype, array $rules): bool
    {
        if (!isset($this->items[$sec][$ptype])) {
            return false;
        }

        foreach ($rules as $rule) {
            $this->removePolicy($sec, $ptype, $rule);
        }

        return true;
    }

    /**
     * Removes policy rules based on field filters from the model.
     *
     * @param string $sec
     * @param string $ptype
     * @param int $fieldIndex
     * @param string ...$fieldValues
     *
     * If more than one rule is removed, return the removed rule array, otherwise return false
     * @return string[][]|false
     */
    public function removeFilteredPolicy(string $sec, string $ptype, int $fieldIndex, string ...$fieldValues)
    {
        $tmp = [];
        $effects = [];
        $res = false;

        if (!isset($this->items[$sec][$ptype])) {
            return $res;
        }

        $this->items[$sec][$ptype]->policyMap = [];

        foreach ($this->items[$sec][$ptype]->policy as $index => $rule) {
            $matched = true;
            foreach ($fieldValues as $i => $fieldValue) {
                if ('' != $fieldValue && $rule[$fieldIndex + intval($i)] != $fieldValue) {
                    $matched = false;
                    break;
                }
            }

            if ($matched) {
                $effects[] = $rule;
            } else {
                $tmp[] = $rule;
                $this->items[$sec][$ptype]->policyMap[implode(self::DEFAULT_SEP, $rule)] = count($tmp) - 1;
            }
        }

        if (count($tmp) != count($this->items[$sec][$ptype]->policy)) {
            $this->items[$sec][$ptype]->policy = $tmp;
            $res = true;
        }

        return $res ? $effects : false;
    }

    /**
     * Gets all values for a field for all rules in a policy, duplicated values are removed.
     *
     * @param string $sec
     * @param string $ptype
     * @param int $fieldIndex
     *
     * @return string[]
     */
    public function getValuesForFieldInPolicy(string $sec, string $ptype, int $fieldIndex): array
    {
        $values = [];

        if (!isset($this->items[$sec][$ptype])) {
            return $values;
        }

        foreach ($this->items[$sec][$ptype]->policy as $rule) {
            $values[] = $rule[$fieldIndex];
        }

        Util::arrayRemoveDuplicates($values);

        return $values;
    }

    /**
     * Gets all values for a field for all rules in a policy of all ptypes, duplicated values are removed.
     *
     * @param string $sec
     * @param int $fieldIndex
     *
     * @return string[]
     */
    public function getValuesForFieldInPolicyAllTypes(string $sec, int $fieldIndex): array
    {
        $values = [];

        foreach ($this->items[$sec] as $key => $ptype) {
            $values = array_merge($values, $this->getValuesForFieldInPolicy($sec, $key, $fieldIndex));
        }

        Util::arrayRemoveDuplicates($values);

        return $values;
    }

    /**
     * Determine if the given Model option exists.
     *
     * @param string $offset
     *
     * @return bool
     */
    public function offsetExists($offset): bool
    {
        return isset($this->items[$offset]);
    }

    /**
     * Get a Model option.
     *
     * @param string $offset
     *
     * @return array<string, Assertion>|null
     */
    public function offsetGet($offset): ?array
    {
        return $this->items[$offset] ?? null;
    }

    /**
     * Set a Model option.
     *
     * @param string $offset
     * @param array<string, Assertion> $value
     */
    public function offsetSet($offset, $value): void
    {
        $this->items[$offset] = $value;
    }

    /**
     * Unset a Model option.
     *
     * @param string $offset
     */
    public function offsetUnset($offset): void
    {
        unset($this->items[$offset]);
    }
}
