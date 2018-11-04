<?php

namespace Casbin\Util;

use Casbin\Rbac\RoleManager;
use IPTools\IP;
use IPTools\Range;

/**
 * BuiltinOperations.
 *
 * @author techlee@qq.com
 */
class BuiltinOperations
{
    public static function keyMatch($key1, $key2)
    {
        if (false === strpos($key2, '*')) {
            return $key1 == $key2;
        }

        $needle = rtrim($key2, '*');

        return substr($key1, 0, \strlen($needle)) === (string) $needle;
    }

    public static function keyMatchFunc(...$args)
    {
        $name1 = $args[0];
        $name2 = $args[1];

        return self::keyMatch($name1, $name2);
    }

    public static function keyMatch2($key1, $key2)
    {
        $key2 = str_replace(['/*'], ['/.*'], $key2);

        $pattern = '/(.*):[^\/]+(.*)/';
        for (; ;) {
            if (false === strpos($key2, '/:')) {
                break;
            }
            $key2 = preg_replace_callback(
                $pattern,
                function ($m) {
                    return $m[1].'[^\/]+'.$m[2];
                },
                $key2
            );
            $key2 = '^'.$key2.'$';
        }

        return self::regexMatch($key1, $key2);
    }

    public static function keyMatch2Func(...$args)
    {
        $name1 = $args[0];
        $name2 = $args[1];

        return self::keyMatch2($name1, $name2);
    }

    public static function keyMatch3($key1, $key2)
    {
        $key2 = str_replace(['/*'], ['/.*'], $key2);

        $pattern = '/(.*)\{[^\/]+\}(.*)/';
        for (; ;) {
            if (false === strpos($key2, '/{')) {
                break;
            }
            $key2 = preg_replace_callback(
                $pattern,
                function ($m) {
                    return $m[1].'[^\/]+'.$m[2];
                },
                $key2
            );
        }

        return self::regexMatch($key1, $key2);
    }

    public static function keyMatch3Func(...$args)
    {
        $name1 = $args[0];
        $name2 = $args[1];

        return self::keyMatch3($name1, $name2);
    }

    public static function regexMatch($key1, $key2)
    {
        return preg_match('~'.$key2.'~', $key1);
    }

    public static function regexMatchFunc(...$args)
    {
        $name1 = $args[0];
        $name2 = $args[1];

        return self::regexMatch($name1, $name2);
    }

    public static function iPMatch($ip1, $ip2)
    {
        $objIP1 = IP::parse($ip1);

        $objIP2 = Range::parse($ip2);

        return $objIP2->contains($objIP1);
    }

    public static function iPMatchFunc(...$args)
    {
        $ip1 = $args[0];
        $ip2 = $args[1];

        return self::iPMatch($ip1, $ip2);
    }

    public static function generateGFunction(RoleManager $rm)
    {
        return function (...$args) use ($rm) {
            $name1 = $args[0];
            $name2 = $args[1];

            if (null === $rm) {
                return $name1 == $name2;
            } elseif (2 == \count($args)) {
                $res = $rm->hasLink($name1, $name2);

                return $res;
            } else {
                $domain = (string) $args[2];
                $res = $rm->hasLink($name1, $name2, $domain);

                return $res;
            }
        };
    }
}
