<?php

declare(strict_types=1);

namespace Casbin;

use Closure;

/**
 * ManagementEnforcer = InternalEnforcer + Management API.
 *
 * @author techlee@qq.com
 */
class ManagementEnforcer extends InternalEnforcer
{
    /**
     * Gets the list of subjects that show up in the current policy.
     *
     * @return array
     */
    public function getAllSubjects(): array
    {
        return $this->model->getValuesForFieldInPolicyAllTypes('p', 0);
    }

    /**
     * Gets the list of subjects that show up in the current named policy.
     *
     * @param string $ptype
     *
     * @return array
     */
    public function getAllNamedSubjects(string $ptype): array
    {
        return $this->model->getValuesForFieldInPolicy('p', $ptype, 0);
    }

    /**
     * Gets the list of objects that show up in the current policy.
     *
     * @return array
     */
    public function getAllObjects(): array
    {
        return $this->model->getValuesForFieldInPolicyAllTypes('p', 1);
    }

    /**
     * Gets the list of objects that show up in the current named policy.
     *
     * @param string $ptype
     *
     * @return array
     */
    public function getAllNamedObjects(string $ptype): array
    {
        return $this->model->getValuesForFieldInPolicy('p', $ptype, 1);
    }

    /**
     * Gets the list of actions that show up in the current policy.
     *
     * @return array
     */
    public function getAllActions(): array
    {
        return $this->model->getValuesForFieldInPolicyAllTypes('p', 2);
    }

    /**
     * Gets the list of actions that show up in the current named policy.
     *
     * @param string $ptype
     *
     * @return array
     */
    public function getAllNamedActions(string $ptype): array
    {
        return $this->model->getValuesForFieldInPolicy('p', $ptype, 2);
    }

    /**
     * Gets the list of roles that show up in the current policy.
     *
     * @return array
     */
    public function getAllRoles(): array
    {
        return $this->model->getValuesForFieldInPolicyAllTypes('g', 1);
    }

    /**
     * Gets the list of roles that show up in the current named policy.
     *
     * @param string $ptype
     *
     * @return array
     */
    public function getAllNamedRoles(string $ptype): array
    {
        return $this->model->getValuesForFieldInPolicy('g', $ptype, 1);
    }

    /**
     * Gets all the authorization rules in the policy.
     *
     * @return array
     */
    public function getPolicy(): array
    {
        return $this->getNamedPolicy('p');
    }

    /**
     * Gets all the authorization rules in the policy, field filters can be specified.
     *
     * @param int $fieldIndex
     * @param string ...$fieldValues
     *
     * @return array
     */
    public function getFilteredPolicy(int $fieldIndex, string ...$fieldValues): array
    {
        return $this->getFilteredNamedPolicy('p', $fieldIndex, ...$fieldValues);
    }

    /**
     * Gets all the authorization rules in the named policy.
     *
     * @param string $ptype
     *
     * @return array
     */
    public function getNamedPolicy(string $ptype): array
    {
        return $this->model->getPolicy('p', $ptype);
    }

    /**
     * Gets all the authorization rules in the named policy, field filters can be specified.
     *
     * @param string $ptype
     * @param int $fieldIndex
     * @param string ...$fieldValues
     *
     * @return array
     */
    public function getFilteredNamedPolicy(string $ptype, int $fieldIndex, string ...$fieldValues): array
    {
        return $this->model->getFilteredPolicy('p', $ptype, $fieldIndex, ...$fieldValues);
    }

    /**
     * Gets all the role inheritance rules in the policy.
     *
     * @return array
     */
    public function getGroupingPolicy(): array
    {
        return $this->getNamedGroupingPolicy('g');
    }

    /**
     * Gets all the role inheritance rules in the policy, field filters can be specified.
     *
     * @param int $fieldIndex
     * @param string ...$fieldValues
     *
     * @return array
     */
    public function getFilteredGroupingPolicy(int $fieldIndex, string ...$fieldValues): array
    {
        return $this->getFilteredNamedGroupingPolicy('g', $fieldIndex, ...$fieldValues);
    }

    /**
     * Gets all the role inheritance rules in the policy.
     *
     * @param string $ptype
     *
     * @return array
     */
    public function getNamedGroupingPolicy(string $ptype): array
    {
        return $this->model->getPolicy('g', $ptype);
    }

    /**
     * Gets all the role inheritance rules in the policy, field filters can be specified.
     *
     * @param string $ptype
     * @param int $fieldIndex
     * @param string ...$fieldValues
     *
     * @return array
     */
    public function getFilteredNamedGroupingPolicy(string $ptype, int $fieldIndex, string ...$fieldValues): array
    {
        return $this->model->getFilteredPolicy('g', $ptype, $fieldIndex, ...$fieldValues);
    }

    /**
     * Determines whether an authorization rule exists.
     *
     * @param mixed ...$params
     *
     * @return bool
     */
    public function hasPolicy(...$params): bool
    {
        return $this->hasNamedPolicy('p', ...$params);
    }

    /**
     * Determines whether a named authorization rule exists.
     *
     * @param string $ptype
     * @param mixed ...$params
     *
     * @return bool
     */
    public function hasNamedPolicy(string $ptype, ...$params): bool
    {
        if (1 == count($params) && is_array($params[0])) {
            $params = $params[0];
        }

        return $this->model->hasPolicy('p', $ptype, $params);
    }

    /**
     * AddPolicy adds an authorization rule to the current policy.
     * If the rule already exists, the function returns false and the rule will not be added.
     * Otherwise the function returns true by adding the new rule.
     *
     * @param mixed ...$params
     *
     * @return bool
     */
    public function addPolicy(...$params): bool
    {
        return $this->addNamedPolicy('p', ...$params);
    }

    /**
     * AddPolicies adds authorization rules to the current policy.
     * If the rule already exists, the function returns false for the corresponding rule and the rule will not be added.
     * Otherwise the function returns true for the corresponding rule by adding the new rule.
     *
     * @param string[][] $rules
     *
     * @return bool
     * @throws Exceptions\CasbinException
     */
    public function addPolicies(array $rules): bool
    {
        return $this->addNamedPolicies('p', $rules);
    }

    /**
     * AddNamedPolicy adds an authorization rule to the current named policy.
     * If the rule already exists, the function returns false and the rule will not be added.
     * Otherwise the function returns true by adding the new rule.
     *
     * @param string $ptype
     * @param mixed ...$params
     *
     * @return bool
     */
    public function addNamedPolicy(string $ptype, ...$params): bool
    {
        if (1 == count($params) && is_array($params[0])) {
            $params = $params[0];
        }

        return $this->addPolicyInternal('p', $ptype, $params);
    }

    /**
     * AddNamedPolicies adds authorization rules to the current named policy.
     * If the rule already exists, the function returns false for the corresponding rule and the rule will not be added.
     * Otherwise the function returns true for the corresponding by adding the new rule.
     *
     * @param string $ptype
     * @param string[][] $rules
     *
     * @return bool
     * @throws Exceptions\CasbinException
     */
    public function addNamedPolicies(string $ptype, array $rules): bool
    {
        return $this->addPoliciesInternal('p', $ptype, $rules);
    }

    /**
     * Removes an authorization rule from the current policy.
     *
     * @param mixed ...$params
     *
     * @return bool
     */
    public function removePolicy(...$params): bool
    {
        return $this->removeNamedPolicy('p', ...$params);
    }

    /**
     * Removes an authorization rules from the current policy.
     *
     * @param array $rules
     *
     * @return bool
     */
    public function removePolicies(array $rules): bool
    {
        return $this->removeNamedPolicies('p', $rules);
    }

    /**
     * Removes an authorization rule from the current policy.
     *
     * @param string[] $oldRule
     * @param string[] $newRule
     *
     * @return bool
     */
    public function updatePolicy(array $oldRule, array $newRule): bool
    {
        return $this->updateNamedPolicy("p", $oldRule, $newRule);
    }

    /**
     * Updates an authorization rule from the current policy.
     *
     * @param string $ptype
     * @param string[] $oldRule
     * @param string[] $newRule
     *
     * @return bool
     */
    public function updateNamedPolicy(string $ptype, array $oldRule, array $newRule): bool
    {
        return $this->updatePolicyInternal("p", $ptype, $oldRule, $newRule);
    }

    /**
     * UpdatePolicies updates authorization rules from the current policies.
     *
     * @param string[][] $oldPolices
     * @param string[][] $newPolicies
     * @return boolean
     */
    public function updatePolicies(array $oldPolices, array $newPolicies): bool
    {
        return $this->updateNamedPolicies("p", $oldPolices, $newPolicies);
    }

    /**
     * Updates authorization rules from the current policy.
     *
     * @param string $ptype
     * @param string[][] $oldPolices
     * @param string[][] $newPolicies
     * @return boolean
     */
    public function updateNamedPolicies(string $ptype, array $oldPolices, array $newPolicies): bool
    {
        return $this->updatePoliciesInternal("p", $ptype, $oldPolices, $newPolicies);
    }

    public function updateFilteredPolicies(array $newPolicies, int $fieldIndex, string ...$fieldValues): bool
    {
        return $this->updateFilteredNamedPolicies("p", $newPolicies, $fieldIndex, ...$fieldValues);
    }

    /**
     * Undocumented function
     *
     * @param string $ptype
     * @param array $newPolicies
     * @param integer $fieldIndex
     * @param string ...$fieldValues
     * @return boolean
     */
    public function updateFilteredNamedPolicies(string $ptype, array $newPolicies, int $fieldIndex, string ...$fieldValues): bool
    {
        return $this->updateFilteredPoliciesInternal("p", $ptype, $newPolicies, $fieldIndex, ...$fieldValues);
    }

    /**
     * Removes an authorization rule from the current policy, field filters can be specified.
     *
     * @param int $fieldIndex
     * @param string ...$fieldValues
     *
     * @return bool
     */
    public function removeFilteredPolicy(int $fieldIndex, string ...$fieldValues): bool
    {
        return $this->removeFilteredNamedPolicy('p', $fieldIndex, ...$fieldValues);
    }

    /**
     * Removes an authorization rule from the current named policy.
     *
     * @param string $ptype
     * @param mixed ...$params
     *
     * @return bool
     */
    public function removeNamedPolicy(string $ptype, ...$params): bool
    {
        if (1 == count($params) && is_array($params[0])) {
            $params = $params[0];
        }

        return $this->removePolicyInternal('p', $ptype, $params);
    }

    /**
     * Removes an authorization rules from the current named policy.
     *
     * @param string $ptype
     * @param array $rules
     *
     * @return bool
     */
    public function removeNamedPolicies(string $ptype, array $rules): bool
    {
        return $this->removePoliciesInternal('p', $ptype, $rules);
    }

    /**
     * Removes an authorization rule from the current named policy, field filters can be specified.
     *
     * @param string $ptype
     * @param int $fieldIndex
     * @param string ...$fieldValues
     *
     * @return bool
     */
    public function removeFilteredNamedPolicy(string $ptype, int $fieldIndex, string ...$fieldValues): bool
    {
        return $this->removeFilteredPolicyInternal('p', $ptype, $fieldIndex, ...$fieldValues);
    }

    /**
     * Determines whether a role inheritance rule exists.
     *
     * @param mixed ...$params
     *
     * @return bool
     */
    public function hasGroupingPolicy(...$params): bool
    {
        return $this->hasNamedGroupingPolicy('g', ...$params);
    }

    /**
     * Determines whether a named role inheritance rule exists.
     *
     * @param string $ptype
     * @param mixed ...$params
     *
     * @return bool
     */
    public function hasNamedGroupingPolicy(string $ptype, ...$params): bool
    {
        if (1 == count($params) && is_array($params[0])) {
            $params = $params[0];
        }

        return $this->model->hasPolicy('g', $ptype, $params);
    }

    /**
     * AddGroupingPolicy adds a role inheritance rule to the current policy.
     * If the rule already exists, the function returns false and the rule will not be added.
     * Otherwise the function returns true by adding the new rule.
     *
     * @param mixed ...$params
     *
     * @return bool
     */
    public function addGroupingPolicy(...$params): bool
    {
        return $this->addNamedGroupingPolicy('g', ...$params);
    }

    /**
     * AddGroupingPolicy adds a role inheritance rules to the current policy.
     * If the rule already exists, the function returns false and the rule will not be added.
     * Otherwise the function returns true by adding the new rule.
     *
     * @param array $rules
     *
     * @return bool
     */
    public function addGroupingPolicies(array $rules): bool
    {
        return $this->addNamedGroupingPolicies('g', $rules);
    }

    /**
     * AddNamedGroupingPolicy adds a named role inheritance rule to the current policy.
     * If the rule already exists, the function returns false and the rule will not be added.
     * Otherwise the function returns true by adding the new rule.
     *
     * @param string $ptype
     * @param mixed ...$params
     *
     * @return bool
     */
    public function addNamedGroupingPolicy(string $ptype, ...$params): bool
    {
        if (1 == count($params) && is_array($params[0])) {
            $params = $params[0];
        }

        $ruleAdded = $this->addPolicyInternal('g', $ptype, $params);

        if ($this->autoBuildRoleLinks) {
            $this->buildRoleLinks();
        }

        return $ruleAdded;
    }

    /**
     * AddNamedGroupingPolicy adds a named role inheritance rules to the current policy.
     * If the rule already exists, the function returns false and the rule will not be added.
     * Otherwise the function returns true by adding the new rule.
     *
     * @param string $ptype
     * @param array $rules
     *
     * @return bool
     */
    public function addNamedGroupingPolicies(string $ptype, array $rules): bool
    {
        $ruleAdded = $this->addPoliciesInternal('g', $ptype, $rules);

        if ($this->autoBuildRoleLinks) {
            $this->buildRoleLinks();
        }

        return $ruleAdded;
    }

    /**
     * Removes a role inheritance rule from the current policy.
     *
     * @param mixed ...$params
     *
     * @return bool
     */
    public function removeGroupingPolicy(...$params): bool
    {
        return $this->removeNamedGroupingPolicy('g', ...$params);
    }

    /**
     * Removes a role inheritance rules from the current policy.
     *
     * @param array $rules
     *
     * @return bool
     */
    public function removeGroupingPolicies(array $rules): bool
    {
        return $this->removeNamedGroupingPolicies('g', $rules);
    }

    /**
     * Removes a role inheritance rule from the current policy, field filters can be specified.
     *
     * @param int $fieldIndex
     * @param string ...$fieldValues
     *
     * @return bool
     */
    public function removeFilteredGroupingPolicy(int $fieldIndex, string ...$fieldValues): bool
    {
        return $this->removeFilteredNamedGroupingPolicy('g', $fieldIndex, ...$fieldValues);
    }

    /**
     * Removes a role inheritance rule from the current named policy.
     *
     * @param string $ptype
     * @param mixed ...$params
     *
     * @return bool
     */
    public function removeNamedGroupingPolicy(string $ptype, ...$params): bool
    {
        if (1 == count($params) && is_array($params[0])) {
            $params = $params[0];
        }

        $ruleRemoved = $this->removePolicyInternal('g', $ptype, $params);

        if ($this->autoBuildRoleLinks) {
            $this->buildRoleLinks();
        }

        return $ruleRemoved;
    }

    /**
     * Removes a role inheritance rules from the current named policy.
     *
     * @param string $ptype
     * @param array $rules
     *
     * @return bool
     */
    public function removeNamedGroupingPolicies(string $ptype, array $rules): bool
    {
        $ruleRemoved = $this->removePoliciesInternal('g', $ptype, $rules);

        if ($this->autoBuildRoleLinks) {
            $this->buildRoleLinks();
        }

        return $ruleRemoved;
    }

    /**
     * Removes a role inheritance rule from the current named policy, field filters can be specified.
     *
     * @param string $ptype
     * @param int $fieldIndex
     * @param string ...$fieldValues
     *
     * @return bool
     */
    public function removeFilteredNamedGroupingPolicy(string $ptype, int $fieldIndex, string ...$fieldValues): bool
    {
        $ruleRemoved = $this->removeFilteredPolicyInternal('g', $ptype, $fieldIndex, ...$fieldValues);

        if ($this->autoBuildRoleLinks) {
            $this->buildRoleLinks();
        }

        return $ruleRemoved;
    }

    /**
     * Adds a customized function.
     *
     * @param string $name
     * @param Closure $func
     */
    public function addFunction(string $name, Closure $func): void
    {
        $this->fm->addFunction($name, $func);
    }
}
