<?php

namespace Casbin;

/**
 * CachedEnforcer wraps Enforcer and provides decision cache.
 *
 * @author techlee@qq.com
 */
class CachedEnforcer extends Enforcer
{
    public static $m = [];

    protected $enableCache;

    protected static $locker;

    public function __construct(...$params)
    {
        parent::__construct(...$params);
        $this->enableCache = true;
    }

    // EnableCache determines whether to enable cache on Enforce(). When enableCache is enabled, cached result (true | false) will be returned for previous decisions.
    public function enableCache($enableCache)
    {
        $this->enableCache = $enableCache;
    }

    // Enforce decides whether a "subject" can access a "object" with the operation "action", input parameters are usually: (sub, obj, act).
    // if rvals is not string , ingore the cache
    public function enforce(...$rvals)
    {
        if (!$this->enableCache) {
            return parent::enforce(...$rvals);
        }

        $key = '';
        foreach ($rvals as $rval) {
            if (is_string($rval)) {
                $key .= $rval.'$$';
            } else {
                return  parent::enforce(...$rvals);
            }
        }

        if (isset(self::$m[$key])) {
            return self::$m[$key];
        } else {
            $res = parent::enforce(...$rvals);
            self::$m[$key] = $res;

            return $res;
        }
    }

    // InvalidateCache deletes all the existing cached decisions.
    public function invalidateCache()
    {
        self::$m = [];
    }
}
