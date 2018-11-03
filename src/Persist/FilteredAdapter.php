<?php

namespace Casbin\Persist;

use Casbin\Model\Model;

/**
 * FilteredAdapter interface.
 *
 * @author techlee@qq.com
 */
interface FilteredAdapter extends Adapter
{
    public function loadFilteredPolicy(Model $model, $filter);

    public function isFiltered();
}
