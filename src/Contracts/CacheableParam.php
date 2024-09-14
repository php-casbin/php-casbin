<?php

declare(strict_types=1);

namespace Casbin\Contracts;

/**
 * Interface CacheableParam.
 * 
 * @author 1692898084@qq.com
 */
interface CacheableParam
{
    /**
     * Returns a cache key.
     *
     * @return string
     */
    public function getCacheKey(): string;
}