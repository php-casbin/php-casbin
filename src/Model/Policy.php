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
    const DEFAULT_SEP = ",";

    /**
     * All of the Model items.
     *
     * @var array<string, array<string, Assertion>>
     */
    protected $items = [];

    /**
     * Initializes the roles in RBAC.
     *
     * @param RoleManager $rm
     * @throws CasbinException
     */
    public function buildRoleLinks(RoleManager $rm): void
    {
        if (!isset($this->items['g'])) {
            return;
        }

        foreach ($this->items['g'] as $ast) {
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
                if ('' != $fieldValue && $rule[$fieldIndex + $i] != $fieldValue) {
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
        $this->items[$sec][$ptype]->policy[] = $rule;
        $this->items[$sec][$ptype]->policyMap[implode(self::DEFAULT_SEP, $rule)] = count($this->items[$sec][$ptype]->policy) - 1;
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

            $this->items[$sec][$ptype]->policy[] = $rule;
            $this->items[$sec][$ptype]->policyMap[$hashKey] = count($this->items[$sec][$ptype]->policy) - 1;
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
        $firstIndex = -1;

        if (!isset($this->items[$sec][$ptype])) {
            return $res;
        }

        foreach ($this->items[$sec][$ptype]->policy as $index => $rule) {
            $matched = true;
            foreach ($fieldValues as $i => $fieldValue) {
                if ('' != $fieldValue && $rule[$fieldIndex + $i] != $fieldValue) {
                    $matched = false;
                    break;
                }
            }

            if ($matched) {
                if ($firstIndex == -1) {
                    $firstIndex = $index;
                }
                unset($this->items[$sec][$ptype]->policyMap[implode(self::DEFAULT_SEP, $rule)]);
                $effects[] = $rule;
                $res = true;
            } else {
                $tmp[] = $rule;
            }
        }

        if ($fieldIndex != -1) {
            $this->items[$sec][$ptype]->policy = $tmp;
            $count = count($this->items[$sec][$ptype]->policy);
            for ($i = $fieldIndex; $i < $count; $i++) {
                $this->items[$sec][$ptype]->policyMap[implode(self::DEFAULT_SEP, $this->items[$sec][$ptype]->policy[$i])] = $i;
            }
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
     * @param mixed $offset
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
     * @param mixed $offset
     *
     * @return array<string, Assertion>|null
     */
    public function offsetGet($offset): ?array
    {
        return isset($this->items[$offset]) ? $this->items[$offset] : null;
    }

    /**
     * Set a Model option.
     *
     * @param mixed $offset
     * @param mixed $value
     */
    public function offsetSet($offset, $value)
    {
        $this->items[$offset] = $value;
    }

    /**
     * Unset a Model option.
     *
     * @param mixed $offset
     */
    public function offsetUnset($offset)
    {
        unset($this->items[$offset]);
    }
}
