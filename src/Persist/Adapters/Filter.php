<?php

declare(strict_types=1);

namespace Casbin\Persist\Adapters;

/**
 * Filter defines the filtering rules for a FilteredAdapter's policy. Empty values
 * are ignored, but all others must match the filter.
 *
 * @author techlee@qq.com
 */
class Filter
{
    /**
     * $p variable.
     *
     * @var array
     */
    public $p = [];

    /**
     * $g variable.
     *
     * @var array
     */
    public $g = [];

    /**
     * __construct function.
     *
     * @param array $p
     * @param array $g
     */
    public function __construct(array $p = [], array $g = [])
    {
        $this->p = $p;
        $this->g = $g;
    }
}
