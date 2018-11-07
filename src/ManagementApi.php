<?php

namespace Casbin;

trait ManagementApi
{
    // GetAllSubjects gets the list of subjects that show up in the current policy.
    public function getAllSubjects()
    {
        return $this->getAllNamedSubjects('p');
    }

    // GetAllNamedSubjects gets the list of subjects that show up in the current named policy.
    public function getAllNamedSubjects($ptype)
    {
        return $this->model->getValuesForFieldInPolicy('p', $ptype, 0);
    }

    // GetAllObjects gets the list of objects that show up in the current policy.
    public function getAllObjects()
    {
        return $this->getAllNamedObjects('p');
    }

    // GetAllNamedObjects gets the list of objects that show up in the current named policy.
    public function getAllNamedObjects($ptype)
    {
        return $this->model->getValuesForFieldInPolicy('p', $ptype, 1);
    }

    // GetAllActions gets the list of actions that show up in the current policy.
    public function getAllActions()
    {
        return $this->getAllNamedActions('p');
    }

    // GetAllNamedActions gets the list of actions that show up in the current named policy.
    public function getAllNamedActions($ptype)
    {
        return $this->model->getValuesForFieldInPolicy('p', $ptype, 2);
    }

    // GetAllRoles gets the list of roles that show up in the current policy.
    public function getAllRoles()
    {
        return $this->getAllNamedRoles('g');
    }

    // GetAllNamedRoles gets the list of roles that show up in the current named policy.
    public function getAllNamedRoles($ptype)
    {
        return $this->model->getValuesForFieldInPolicy('g', $ptype, 1);
    }

    // GetPolicy gets all the authorization rules in the policy.
    public function getPolicy()
    {
        return $this->getNamedPolicy('p');
    }

    // GetFilteredPolicy gets all the authorization rules in the policy, field filters can be specified.
    public function getFilteredPolicy($fieldIndex, ...$fieldValues)
    {
        return $this->getFilteredNamedPolicy('p', $fieldIndex, ...$fieldValues);
    }

    // GetNamedPolicy gets all the authorization rules in the named policy.
    public function getNamedPolicy($ptype)
    {
        return $this->model->getPolicy('p', $ptype);
    }

    // GetFilteredNamedPolicy gets all the authorization rules in the named policy, field filters can be specified.
    public function getFilteredNamedPolicy($ptype, $fieldIndex, ...$fieldValues)
    {
        return $this->model->getFilteredPolicy('p', $ptype, $fieldIndex, ...$fieldValues);
    }

    // GetGroupingPolicy gets all the role inheritance rules in the policy.
    public function getGroupingPolicy()
    {
        return $this->getNamedGroupingPolicy('g');
    }

    // GetFilteredGroupingPolicy gets all the role inheritance rules in the policy, field filters can be specified.
    public function getFilteredGroupingPolicy($fieldIndex, ...$fieldValues)
    {
        return $this->getFilteredNamedGroupingPolicy('g', $fieldIndex, ...$fieldValues);
    }

    // GetNamedGroupingPolicy gets all the role inheritance rules in the policy.
    public function getNamedGroupingPolicy($ptype)
    {
        return $this->model->getPolicy('g', $ptype);
    }

    // GetFilteredNamedGroupingPolicy gets all the role inheritance rules in the policy, field filters can be specified.
    public function getFilteredNamedGroupingPolicy($ptype, $fieldIndex, ...$fieldValues)
    {
        return $this->model->getFilteredPolicy('g', $ptype, $fieldIndex, ...$fieldValues);
    }

    // HasPolicy determines whether an authorization rule exists.
    public function hasPolicy(...$params)
    {
        return $this->hasNamedPolicy('p', ...$params);
    }

    // HasNamedPolicy determines whether a named authorization rule exists.
    public function hasNamedPolicy($ptype, ...$params)
    {
        if (1 == count($params) && is_array($params[0])) {
            $strSlice = $params[0];

            return $this->model->hasPolicy('p', $ptype, $strSlice);
        }

        $policy = [];
        foreach ($params as $param) {
            $policy[] = $param;
        }

        return $this->model->hasPolicy('p', $ptype, $policy);
    }

    // AddPolicy adds an authorization rule to the current policy.
    // If the rule already exists, the function returns false and the rule will not be added.
    // Otherwise the function returns true by adding the new rule.
    public function addPolicy(...$params)
    {
        return $this->addNamedPolicy('p', ...$params);
    }

    // AddNamedPolicy adds an authorization rule to the current named policy.
    // If the rule already exists, the function returns false and the rule will not be added.
    // Otherwise the function returns true by adding the new rule.
    public function addNamedPolicy($ptype, ...$params)
    {
        $ruleAdded = false;
        if (1 == count($params) && is_array($params[0])) {
            $strSlice = $params[0];
            $ruleAdded = $this->addPolicyInternal('p', $ptype, $strSlice);
        } else {
            $policy = [];
            foreach ($params as $param) {
                $policy[] = $param;
            }

            $ruleAdded = $this->addPolicyInternal('p', $ptype, $policy);
        }

        return $ruleAdded;
    }

    // RemovePolicy removes an authorization rule from the current policy.
    public function removePolicy(...$params)
    {
        return $this->removeNamedPolicy('p', ...$params);
    }

    // RemoveFilteredPolicy removes an authorization rule from the current policy, field filters can be specified.
    public function removeFilteredPolicy($fieldIndex, ...$fieldValues)
    {
        return $this->removeFilteredNamedPolicy('p', $fieldIndex, ...$fieldValues);
    }

    // RemoveNamedPolicy removes an authorization rule from the current named policy.
    public function removeNamedPolicy($ptype, ...$params)
    {
        $ruleRemoved = false;
        if (1 == count($params) && is_array($params[0])) {
            $strSlice = $params[0];
            $ruleAdded = $this->removePolicyInternal('p', $ptype, $strSlice);
        } else {
            $policy = [];
            foreach ($params as $param) {
                $policy[] = $param;
            }

            $ruleRemoved = $this->removePolicyInternal('p', $ptype, $policy);
        }

        return $ruleRemoved;
    }

    // RemoveFilteredNamedPolicy removes an authorization rule from the current named policy, field filters can be specified.
    public function removeFilteredNamedPolicy($ptype, $fieldIndex, ...$fieldValues)
    {
        return $this->removeFilteredPolicyInternal('p', $ptype, $fieldIndex, ...$fieldValues);
    }

    // HasGroupingPolicy determines whether a role inheritance rule exists.
    public function hasGroupingPolicy(...$params)
    {
        return $this->hasNamedGroupingPolicy('g', ...$params);
    }

    // HasNamedGroupingPolicy determines whether a named role inheritance rule exists.
    public function hasNamedGroupingPolicy($ptype, ...$params)
    {
        if (1 == count($params) && is_array($params[0])) {
            $strSlice = $params[0];

            return $this->model->hasPolicy('g', $ptype, $strSlice);
        }

        $policy = [];
        foreach ($params as $param) {
            $policy[] = $param;
        }

        return $this->model->hasPolicy('g', $ptype, $policy);
    }

    // AddGroupingPolicy adds a role inheritance rule to the current policy.
    // If the rule already exists, the function returns false and the rule will not be added.
    // Otherwise the function returns true by adding the new rule.
    public function addGroupingPolicy(...$params)
    {
        return $this->addNamedGroupingPolicy('g', ...$params);
    }

    // AddNamedGroupingPolicy adds a named role inheritance rule to the current policy.
    // If the rule already exists, the function returns false and the rule will not be added.
    // Otherwise the function returns true by adding the new rule.
    public function addNamedGroupingPolicy($ptype, ...$params)
    {
        $ruleAdded = false;
        if (1 == count($params) && is_array($params[0])) {
            $strSlice = $params[0];
            $ruleAdded = $this->addPolicyInternal('g', $ptype, $strSlice);
        } else {
            $policy = [];
            foreach ($params as $param) {
                $policy[] = $param;
            }

            $ruleAdded = $this->addPolicyInternal('g', $ptype, $policy);
        }

        if ($this->autoBuildRoleLinks) {
            $this->buildRoleLinks();
        }

        return $ruleAdded;
    }

    // RemoveGroupingPolicy removes a role inheritance rule from the current policy.
    public function removeGroupingPolicy(...$params)
    {
        return $this->removeNamedGroupingPolicy('g', ...$params);
    }

    // RemoveFilteredGroupingPolicy removes a role inheritance rule from the current policy, field filters can be specified.
    public function removeFilteredGroupingPolicy($fieldIndex, ...$fieldValues)
    {
        return $this->removeFilteredNamedGroupingPolicy('g', $fieldIndex, ...$fieldValues);
    }

    // RemoveNamedGroupingPolicy removes a role inheritance rule from the current named policy.
    public function removeNamedGroupingPolicy($ptype, ...$params)
    {
        $ruleRemoved = false;
        if (1 == count($params) && is_array($params[0])) {
            $strSlice = $params[0];
            $ruleRemoved = $this->removePolicyInternal('g', $ptype, $strSlice);
        } else {
            $policy = [];
            foreach ($params as $param) {
                $policy[] = $param;
            }

            $ruleRemoved = $this->removePolicyInternal('g', $ptype, $policy);
        }

        if ($this->autoBuildRoleLinks) {
            $this->buildRoleLinks();
        }

        return $ruleRemoved;
    }

    // RemoveFilteredNamedGroupingPolicy removes a role inheritance rule from the current named policy, field filters can be specified.
    public function removeFilteredNamedGroupingPolicy($ptype, $fieldIndex, ...$fieldValues)
    {
        $ruleRemoved = $this->removeFilteredPolicyInternal('g', $ptype, $fieldIndex, ...$fieldValues);

        if ($this->autoBuildRoleLinks) {
            $this->buildRoleLinks();
        }

        return $ruleRemoved;
    }

    // AddFunction adds a customized function.
    public function addFunction($name, \Closure $func)
    {
        $this->fm->addFunction($name, $func);
    }
}
