<?php

declare(strict_types=1);

namespace Casbin;

use Casbin\Contracts\CacheableParam;
use Casbin\Exceptions\CasbinException;
use Casbin\Log\Log;
use Casbin\Model\Model;
use Casbin\Persist\Adapter;
use Psr\Cache\CacheItemPoolInterface;
use Symfony\Component\Cache\Adapter\ArrayAdapter;

/**
 * Class CachedEnforcer
 * Wraps Enforcer and provides decision cache.
 * It is implemented using Symfony's Cache component, which supports multiple cache adapters such as 
 * filesystem, Redis, or Memcached. By default, it uses the `FilesystemAdapter` for local file-based caching.
 *
 * @author techlee@qq.com
 * @author 1692898084@qq.com
 */
class CachedEnforcer extends Enforcer
{
    /**
     * @var int|null
     */
    protected ?int $expireTime;

    /**
     * @var CacheItemPoolInterface
     */
    protected CacheItemPoolInterface $cache;

    /**
     * @var bool
     */
    protected bool $enableCache;

    /**
     * CachedEnforcer constructor.
     *
     * @param string|Model|null $model
     * @param string|Adapter|null $adapter
     * @param bool|null $enableLog
     * 
     * @throws CasbinException
     */
    public function __construct(string|Model|null $model = null, string|Adapter|null $adapter = null, ?bool $enableLog = null)
    {
        $this->enableCache = true;
        $this->cache = new ArrayAdapter();
        $this->expireTime = null;
        parent::__construct($model, $adapter, $enableLog);
    }

    /**
     * Enforce decides whether a "subject" can access a "object" with the operation "action", input parameters are usually: (sub, obj, act).
     * If rvals is not string , ingore the cache.
     *
     * @param mixed ...$rvals
     *
     * @return bool
     *
     * @throws Exceptions\CasbinException
     */
    public function enforce(...$rvals): bool
    {
        if (!$this->enableCache) {
            return parent::enforce(...$rvals);
        }

        $key = $this->getKey(...$rvals);
        $res = $this->getCachedResult($key);
        if (!is_null($res)) {
            return $res;
        }

        $value = parent::enforce(...$rvals);
        $this->setCachedResult($key, $value);
        return $value;
    }

    /**
     * Determines whether to enable cache on Enforce(). When enableCache is enabled, cached result (true | false) will be returned for previous decisions.
     *
     * @param bool $enableCache
     * 
     * @return void
     */
    public function enableCache(bool $enableCache = true): void
    {
        $this->enableCache = $enableCache;
    }


    /**
     * Sets the cache adapter for the enforcer.
     * 
     *
     * @param CacheItemPoolInterface $cache
     * 
     * @return void
     */
    public function setCache(CacheItemPoolInterface $cache): void
    {
        $this->cache = $cache;
    }


    /**
     * Sets the expire time for the cache in seconds. If the value is null, the cache will never expire.
     *
     * @param int|null $expireTime
     * 
     * @return void
     */
    public function setExpireTime(int|null $expireTime): void
    {
        $this->expireTime = $expireTime;
    }

    /**
     * Invalidates the cache.
     */
    public function invalidateCache(): void
    {
        $this->cache->clear();
    }

    /**
     * Reloads the policy from file/database.
     */
    public function loadPolicy(): void
    {
        if ($this->enableCache) {
            $this->cache->clear();
        }

        parent::loadPolicy();
    }

    /**
     * Removes an authorization rule from the current policy.
     *
     * @param mixed ...$params
     *
     * @return bool
     */
    public function removePolicy(...$params): bool
    {
        if ($this->enableCache) {
            $key = $this->getKey(...$params);
            $this->cache->deleteItem($key);
        }

        return parent::removePolicy(...$params);
    }

    /**
     * Removes an authorization rules from the current policy.
     *
     * @param array $rules
     *
     * @return bool
     */
    public function removePolicies(array $rules): bool
    {
        if ($this->enableCache) {
            foreach ($rules as $rule) {
                $key = $this->getKey(...$rule);
                $this->cache->deleteItem($key);
            }
        }

        return parent::removePolicies($rules);
    }

    /**
     * Clears all policy.
     */
    public function clearPolicy(): void
    {
        if ($this->enableCache) {
            if (!$this->cache->clear()) {
                Log::logPrint('clear cache failed');
            }
        }

        parent::clearPolicy();
    }

    /**
     * Gets the cached result from the cache by key.
     *
     * If the key does not exist in the cache, it returns null.
     *
     * @param string $key
     *
     * @return bool|null
     */
    public function getCachedResult(string $key): bool|null
    {
        $value = $this->cache->getItem($key)->get();
        return $value;
    }

    /**
     * Sets the cached result to the cache by key.
     *
     * @param string $key
     * @param bool $value
     *
     * @return void
     */
    public function setCachedResult(string $key, bool $value): void
    {
        $item = $this->cache->getItem($key);
        $item->set($value);
        $item->expiresAfter($this->expireTime);
        $this->cache->save($item);
    }

    /**
     * Gets the cache key by combining the input parameters.
     * 
     * @param mixed ...$rvals
     *
     * @return string
     */
    public function getCacheKey(...$rvals): string
    {
        $key = '';
        foreach ($rvals as $rval) {
            if (is_string($rval)) {
                $key .= $rval;
            } elseif ($rval instanceof CacheableParam) {
                $key .= $rval->getCacheKey();
            } else {
                return '';
            }
            $key .= '$$';
        }

        return $key;
    }

    /**
     * Gets the cache key by combining the input parameters.
     *
     * @param mixed ...$rvals
     *
     * @return string
     */
    private function getKey(...$rvals): string
    {
        return $this->getCacheKey(...$rvals);
    }
}
