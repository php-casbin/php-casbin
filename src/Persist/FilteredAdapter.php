<?php

declare(strict_types=1);

namespace Casbin\Persist;

use Casbin\Model\Model;

/**
 * Interface FilteredAdapter.
 * the filtered file adapter for Casbin. It can load policy from file or save policy to file and supports loading of filtered policies.
 *
 * @author techlee@qq.com
 */
interface FilteredAdapter extends Adapter
{
    /**
     * loads only policy rules that match the filter.
     *
     * @param Model $model
     * @param mixed $filter
     */
    public function loadFilteredPolicy(Model $model, $filter): void;

    /**
     * returns true if the loaded policy has been filtered.
     *
     * @return bool
     */
    public function isFiltered(): bool;
}
