<?php

declare(strict_types=1);

namespace Casbin\Model;

use Casbin\Log\Log;
use Casbin\Rbac\RoleManager;
use Casbin\Util\Util;

/**
 * Trait Policy.
 *
 * @author techlee@qq.com
 */
trait Policy
{
    /**
     * initializes the roles in RBAC.
     *
     * @param RoleManager $rm
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
     * prints the policy to log.
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
     * clears all current policy.
     */
    public function clearPolicy(): void
    {
        foreach (['p', 'g'] as $sec) {
            if (!isset($this->items[$sec])) {
                return;
            }
            foreach ($this->items[$sec] as $key => $ast) {
                $this->items[$sec][$key]->policy = [];
            }
        }
    }

    /**
     * gets all rules in a policy.
     *
     * @param string $sec
     * @param string $ptype
     *
     * @return array
     */
    public function getPolicy(string $sec, string $ptype): array
    {
        return $this->items[$sec][$ptype]->policy;
    }

    /**
     * gets rules based on field filters from a policy.
     *
     * @param string $sec
     * @param string $ptype
     * @param int    $fieldIndex
     * @param string ...$fieldValues
     *
     * @return array
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
     * determines whether a model has the specified policy rule.
     *
     * @param string $sec
     * @param string $ptype
     * @param array  $rule
     *
     * @return bool
     */
    public function hasPolicy(string $sec, string $ptype, array $rule): bool
    {
        if (!isset($this->items[$sec][$ptype])) {
            return false;
        }

        return in_array($rule, $this->items[$sec][$ptype]->policy, true);
    }

    /**
     * adds a policy rule to the model.
     *
     * @param string $sec
     * @param string $ptype
     * @param array  $rule
     *
     * @return bool
     */
    public function addPolicy(string $sec, string $ptype, array $rule): bool
    {
        if (!$this->hasPolicy($sec, $ptype, $rule)) {
            $this->items[$sec][$ptype]->policy[] = $rule;

            return true;
        }

        return false;
    }

    /**
     * removes a policy rule from the model.
     *
     * @param string $sec
     * @param string $ptype
     * @param array  $rule
     *
     * @return bool
     */
    public function removePolicy(string $sec, string $ptype, array $rule): bool
    {
        if (!isset($this->items[$sec][$ptype])) {
            return false;
        }

        $offset = array_search($rule, $this->items[$sec][$ptype]->policy, true);

        if (false === $offset) {
            return false;
        }

        array_splice($this->items[$sec][$ptype]->policy, $offset, 1);

        return true;
    }

    /**
     * removes policy rules based on field filters from the model.
     *
     * @param string $sec
     * @param string $ptype
     * @param int    $fieldIndex
     * @param string ...$fieldValues
     *
     * @return bool
     */
    public function removeFilteredPolicy(string $sec, string $ptype, int $fieldIndex, string ...$fieldValues): bool
    {
        $tmp = [];
        $res = false;

        if (!isset($this->items[$sec][$ptype])) {
            return $res;
        }

        foreach ($this->items[$sec][$ptype]->policy as $rule) {
            $matched = true;
            foreach ($fieldValues as $i => $fieldValue) {
                if ('' != $fieldValue && $rule[$fieldIndex + $i] != $fieldValue) {
                    $matched = false;

                    break;
                }
            }

            if ($matched) {
                $res = true;
            } else {
                $tmp[] = $rule;
            }
        }

        $this->items[$sec][$ptype]->policy = $tmp;

        return $res;
    }

    /**
     * gets all values for a field for all rules in a policy, duplicated values are removed.
     *
     * @param string $sec
     * @param string $ptype
     * @param int    $fieldIndex
     *
     * @return array
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
     * gets all values for a field for all rules in a policy of all ptypes, duplicated values are removed.
     *
     * @param string $sec
     * @param int    $fieldIndex
     *
     * @return array
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
}
