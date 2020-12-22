<?php

declare(strict_types=1);

namespace Casbin\Persist;

/**
 * UpdatableAdapter is the interface for Casbin adapters with add update policy function.
 *
 * @author techlee@qq.com
 */
interface UpdatableAdapter extends Adapter
{
    /**
     * Updates a policy rule from storage.
     * This is part of the Auto-Save feature.
     *
     * @param string $sec
     * @param string $ptype
     * @param string[] $oldRule
     * @param string[] $newPolicy
     */
    public function updatePolicy(string $sec, string $ptype, array $oldRule, array $newPolicy): void;
}