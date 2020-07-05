<?php

declare(strict_types=1);

namespace Casbin;

/**
 * Trait ManagementApi.
 *
 * @author techlee@qq.com
 */
trait ManagementApi
{
    /**
     * gets the list of subjects that show up in the current policy.
     *
     * @return array
     */
    public function getAllSubjects(): array
    {
        return $this->model->getValuesForFieldInPolicyAllTypes('p', 0);
    }

    /**
     * gets the list of subjects that show up in the current named policy.
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
     * gets the list of objects that show up in the current policy.
     *
     * @return array
     */
    public function getAllObjects(): array
    {
        return $this->model->getValuesForFieldInPolicyAllTypes('p', 1);
    }

    /**
     * gets the list of objects that show up in the current named policy.
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
     * gets the list of actions that show up in the current policy.
     *
     * @return array
     */
    public function getAllActions(): array
    {
        return $this->model->getValuesForFieldInPolicyAllTypes('p', 2);
    }

    /**
     * gets the list of actions that show up in the current named policy.
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
     * gets the list of roles that show up in the current policy.
     *
     * @return array
     */
    public function getAllRoles(): array
    {
        return $this->model->getValuesForFieldInPolicyAllTypes('g', 1);
    }

    /**
     * gets the list of roles that show up in the current named policy.
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
     * gets all the authorization rules in the policy.
     *
     * @return array
     */
    public function getPolicy(): array
    {
        return $this->getNamedPolicy('p');
    }

    /**
     * gets all the authorization rules in the policy, field filters can be specified.
     *
     * @param int    $fieldIndex
     * @param string ...$fieldValues
     *
     * @return array
     */
    public function getFilteredPolicy(int $fieldIndex, string ...$fieldValues): array
    {
        return $this->getFilteredNamedPolicy('p', $fieldIndex, ...$fieldValues);
    }

    /**
     * gets all the authorization rules in the named policy.
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
     * gets all the authorization rules in the named policy, field filters can be specified.
     *
     * @param string $ptype
     * @param int    $fieldIndex
     * @param string ...$fieldValues
     *
     * @return array
     */
    public function getFilteredNamedPolicy(string $ptype, int $fieldIndex, string ...$fieldValues): array
    {
        return $this->model->getFilteredPolicy('p', $ptype, $fieldIndex, ...$fieldValues);
    }

    /**
     * gets all the role inheritance rules in the policy.
     *
     * @return array
     */
    public function getGroupingPolicy(): array
    {
        return $this->getNamedGroupingPolicy('g');
    }

    /**
     * gets all the role inheritance rules in the policy, field filters can be specified.
     *
     * @param int    $fieldIndex
     * @param string ...$fieldValues
     *
     * @return array
     */
    public function getFilteredGroupingPolicy(int $fieldIndex, string ...$fieldValues): array
    {
        return $this->getFilteredNamedGroupingPolicy('g', $fieldIndex, ...$fieldValues);
    }

    /**
     * gets all the role inheritance rules in the policy.
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
     * gets all the role inheritance rules in the policy, field filters can be specified.
     *
     * @param string $ptype
     * @param int    $fieldIndex
     * @param string ...$fieldValues
     *
     * @return array
     */
    public function getFilteredNamedGroupingPolicy(string $ptype, int $fieldIndex, string ...$fieldValues): array
    {
        return $this->model->getFilteredPolicy('g', $ptype, $fieldIndex, ...$fieldValues);
    }

    /**
     * determines whether an authorization rule exists.
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
     * determines whether a named authorization rule exists.
     *
     * @param string $ptype
     * @param mixed  ...$params
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
     * AddNamedPolicy adds an authorization rule to the current named policy.
     * If the rule already exists, the function returns false and the rule will not be added.
     * Otherwise the function returns true by adding the new rule.
     *
     * @param string $ptype
     * @param mixed  ...$params
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
     * removes an authorization rule from the current policy.
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
     * removes an authorization rule from the current policy, field filters can be specified.
     *
     * @param int    $fieldIndex
     * @param string ...$fieldValues
     *
     * @return bool
     */
    public function removeFilteredPolicy(int $fieldIndex, string ...$fieldValues): bool
    {
        return $this->removeFilteredNamedPolicy('p', $fieldIndex, ...$fieldValues);
    }

    /**
     * removes an authorization rule from the current named policy.
     *
     * @param string $ptype
     * @param mixed  ...$params
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
     * removes an authorization rule from the current named policy, field filters can be specified.
     *
     * @param string $ptype
     * @param int    $fieldIndex
     * @param string ...$fieldValues
     *
     * @return bool
     */
    public function removeFilteredNamedPolicy(string $ptype, int $fieldIndex, string ...$fieldValues): bool
    {
        return $this->removeFilteredPolicyInternal('p', $ptype, $fieldIndex, ...$fieldValues);
    }

    /**
     * determines whether a role inheritance rule exists.
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
     * determines whether a named role inheritance rule exists.
     *
     * @param string $ptype
     * @param mixed  ...$params
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
     * AddNamedGroupingPolicy adds a named role inheritance rule to the current policy.
     * If the rule already exists, the function returns false and the rule will not be added.
     * Otherwise the function returns true by adding the new rule.
     *
     * @param string $ptype
     * @param mixed  ...$params
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
     * removes a role inheritance rule from the current policy.
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
     * removes a role inheritance rule from the current policy, field filters can be specified.
     *
     * @param int    $fieldIndex
     * @param string ...$fieldValues
     *
     * @return bool
     */
    public function removeFilteredGroupingPolicy(int $fieldIndex, string ...$fieldValues): bool
    {
        return $this->removeFilteredNamedGroupingPolicy('g', $fieldIndex, ...$fieldValues);
    }

    /**
     * removes a role inheritance rule from the current named policy.
     *
     * @param string $ptype
     * @param mixed  ...$params
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
     * removes a role inheritance rule from the current named policy, field filters can be specified.
     *
     * @param string $ptype
     * @param int    $fieldIndex
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
     * adds a customized function.
     *
     * @param string   $name
     * @param \Closure $func
     */
    public function addFunction(string $name, \Closure $func): void
    {
        $this->fm->addFunction($name, $func);
    }
}
