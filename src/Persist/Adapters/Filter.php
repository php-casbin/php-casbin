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
     * @var string[]
     */
    public $p = [];

    /**
     * $g variable.
     *
     * @var string[]
     */
    public $g = [];

    /**
     * __construct function.
     *
     * @param string[] $p
     * @param string[] $g
     */
    public function __construct(array $p = [], array $g = [])
    {
        $this->p = $p;
        $this->g = $g;
    }
}
