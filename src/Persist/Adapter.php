<?php

namespace Casbin\Persist;

/**
 * Adapter interface.
 *
 * @author techlee@qq.com
 */
interface Adapter
{
    public function loadPolicy($model);

    public function savePolicy($model);

    public function addPolicy($sec, $ptype, $rule);

    public function removePolicy($sec, $ptype, $rule);

    public function removeFilteredPolicy($sec, $ptype, $fieldIndex, ...$fieldValues);
}
