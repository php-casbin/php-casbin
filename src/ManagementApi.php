<?php

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
    public function getAllSubjects()
    {
        return $this->getAllNamedSubjects('p');
    }

    /**
     * gets the list of subjects that show up in the current named policy.
     *
     * @param $ptype
     *
     * @return array
     */
    public function getAllNamedSubjects($ptype)
    {
        return $this->model->getValuesForFieldInPolicy('p', $ptype, 0);
    }

    /**
     * gets the list of objects that show up in the current policy.
     *
     * @return array
     */
    public function getAllObjects()
    {
        return $this->getAllNamedObjects('p');
    }

    /**
     * gets the list of objects that show up in the current named policy.
     *
     * @param $ptype
     *
     * @return array
     */
    public function getAllNamedObjects($ptype)
    {
        return $this->model->getValuesForFieldInPolicy('p', $ptype, 1);
    }

    /**
     * gets the list of actions that show up in the current policy.
     *
     * @return array
     */
    public function getAllActions()
    {
        return $this->getAllNamedActions('p');
    }

    /**
     * gets the list of actions that show up in the current named policy.
     *
     * @param $ptype
     *
     * @return array
     */
    public function getAllNamedActions($ptype)
    {
        return $this->model->getValuesForFieldInPolicy('p', $ptype, 2);
    }

    /**
     * gets the list of roles that show up in the current policy.
     *
     * @return array
     */
    public function getAllRoles()
    {
        return $this->getAllNamedRoles('g');
    }

    /**
     * gets the list of roles that show up in the current named policy.
     *
     * @param $ptype
     *
     * @return array
     */
    public function getAllNamedRoles($ptype)
    {
        return $this->model->getValuesForFieldInPolicy('g', $ptype, 1);
    }

    /**
     * gets all the authorization rules in the policy.
     *
     * @return mixed
     */
    public function getPolicy()
    {
        return $this->getNamedPolicy('p');
    }

    /**
     * gets all the authorization rules in the policy, field filters can be specified.
     *
     * @param int   $fieldIndex
     * @param mixed ...$fieldValues
     *
     * @return array
     */
    public function getFilteredPolicy($fieldIndex, ...$fieldValues)
    {
        return $this->getFilteredNamedPolicy('p', $fieldIndex, ...$fieldValues);
    }

    /**
     * gets all the authorization rules in the named policy.
     *
     * @param $ptype
     *
     * @return mixed
     */
    public function getNamedPolicy($ptype)
    {
        return $this->model->getPolicy('p', $ptype);
    }

    /**
     * gets all the authorization rules in the named policy, field filters can be specified.
     *
     * @param $ptype
     * @param $fieldIndex
     * @param mixed ...$fieldValues
     *
     * @return array
     */
    public function getFilteredNamedPolicy($ptype, $fieldIndex, ...$fieldValues)
    {
        return $this->model->getFilteredPolicy('p', $ptype, $fieldIndex, ...$fieldValues);
    }

    /**
     * gets all the role inheritance rules in the policy.
     *
     * @return array
     */
    public function getGroupingPolicy()
    {
        return $this->getNamedGroupingPolicy('g');
    }

    /**
     * gets all the role inheritance rules in the policy, field filters can be specified.
     *
     * @param $fieldIndex
     * @param mixed ...$fieldValues
     *
     * @return array
     */
    public function getFilteredGroupingPolicy($fieldIndex, ...$fieldValues)
    {
        return $this->getFilteredNamedGroupingPolicy('g', $fieldIndex, ...$fieldValues);
    }

    /**
     * gets all the role inheritance rules in the policy.
     *
     * @param $ptype
     *
     * @return array
     */
    public function getNamedGroupingPolicy($ptype)
    {
        return $this->model->getPolicy('g', $ptype);
    }

    /**
     * gets all the role inheritance rules in the policy, field filters can be specified.
     *
     * @param $ptype
     * @param $fieldIndex
     * @param mixed ...$fieldValues
     *
     * @return array
     */
    public function getFilteredNamedGroupingPolicy($ptype, $fieldIndex, ...$fieldValues)
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
    public function hasPolicy(...$params)
    {
        return $this->hasNamedPolicy('p', ...$params);
    }

    /**
     * determines whether a named authorization rule exists.
     *
     * @param $ptype
     * @param mixed ...$params
     *
     * @return bool
     */
    public function hasNamedPolicy($ptype, ...$params)
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
    public function addPolicy(...$params)
    {
        return $this->addNamedPolicy('p', ...$params);
    }

    /**
     * AddNamedPolicy adds an authorization rule to the current named policy.
     * If the rule already exists, the function returns false and the rule will not be added.
     * Otherwise the function returns true by adding the new rule.
     *
     * @param $ptype
     * @param mixed ...$params
     *
     * @return bool
     */
    public function addNamedPolicy($ptype, ...$params)
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
    public function removePolicy(...$params)
    {
        return $this->removeNamedPolicy('p', ...$params);
    }

    /**
     * removes an authorization rule from the current policy, field filters can be specified.
     *
     * @param $fieldIndex
     * @param mixed ...$fieldValues
     *
     * @return bool
     */
    public function removeFilteredPolicy($fieldIndex, ...$fieldValues)
    {
        return $this->removeFilteredNamedPolicy('p', $fieldIndex, ...$fieldValues);
    }

    /**
     * removes an authorization rule from the current named policy.
     *
     * @param $ptype
     * @param mixed ...$params
     *
     * @return bool
     */
    public function removeNamedPolicy($ptype, ...$params)
    {
        if (1 == count($params) && is_array($params[0])) {
            $params = $params[0];
        }

        return $this->removePolicyInternal('p', $ptype, $params);
    }

    /**
     * removes an authorization rule from the current named policy, field filters can be specified.
     *
     * @param $ptype
     * @param $fieldIndex
     * @param mixed ...$fieldValues
     *
     * @return bool
     */
    public function removeFilteredNamedPolicy($ptype, $fieldIndex, ...$fieldValues)
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
    public function hasGroupingPolicy(...$params)
    {
        return $this->hasNamedGroupingPolicy('g', ...$params);
    }

    /**
     * determines whether a named role inheritance rule exists.
     *
     * @param $ptype
     * @param mixed ...$params
     *
     * @return bool
     */
    public function hasNamedGroupingPolicy($ptype, ...$params)
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
    public function addGroupingPolicy(...$params)
    {
        return $this->addNamedGroupingPolicy('g', ...$params);
    }

    /**
     * AddNamedGroupingPolicy adds a named role inheritance rule to the current policy.
     * If the rule already exists, the function returns false and the rule will not be added.
     * Otherwise the function returns true by adding the new rule.
     *
     * @param $ptype
     * @param mixed ...$params
     *
     * @return bool
     */
    public function addNamedGroupingPolicy($ptype, ...$params)
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
    public function removeGroupingPolicy(...$params)
    {
        return $this->removeNamedGroupingPolicy('g', ...$params);
    }

    /**
     * removes a role inheritance rule from the current policy, field filters can be specified.
     *
     * @param $fieldIndex
     * @param mixed ...$fieldValues
     *
     * @return bool
     */
    public function removeFilteredGroupingPolicy($fieldIndex, ...$fieldValues)
    {
        return $this->removeFilteredNamedGroupingPolicy('g', $fieldIndex, ...$fieldValues);
    }

    /**
     * removes a role inheritance rule from the current named policy.
     *
     * @param $ptype
     * @param mixed ...$params
     *
     * @return bool
     */
    public function removeNamedGroupingPolicy($ptype, ...$params)
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
     * @param mixed  ...$fieldValues
     *
     * @return bool
     */
    public function removeFilteredNamedGroupingPolicy($ptype, $fieldIndex, ...$fieldValues)
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
     * @param $name
     * @param \Closure $func
     */
    public function addFunction($name, \Closure $func)
    {
        $this->fm->addFunction($name, $func);
    }
}
