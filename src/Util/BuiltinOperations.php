<?php

namespace Casbin\Util;

use Casbin\Rbac\RoleManager;
use IPTools\IP;
use IPTools\Range;

/**
 * Class BuiltinOperations.
 *
 * @author techlee@qq.com
 */
class BuiltinOperations
{
    /**
     * determines whether key1 matches the pattern of key2 (similar to RESTful path), key2 can contain a *.
     * For example, "/foo/bar" matches "/foo/*".
     *
     * @param string $key1
     * @param string $key2
     *
     * @return bool
     */
    public static function keyMatch($key1, $key2)
    {
        if (false === strpos($key2, '*')) {
            return $key1 == $key2;
        }

        $needle = rtrim($key2, '*');

        return substr($key1, 0, \strlen($needle)) === (string) $needle;
    }

    /**
     * the wrapper for KeyMatch.
     *
     * @param mixed ...$args
     *
     * @return bool
     */
    public static function keyMatchFunc(...$args)
    {
        $name1 = $args[0];
        $name2 = $args[1];

        return self::keyMatch($name1, $name2);
    }

    /**
     * determines whether key1 matches the pattern of key2 (similar to RESTful path), key2 can contain a *.
     * For example, "/foo/bar" matches "/foo/*", "/resource1" matches "/:resource".
     *
     * @param string $key1
     * @param string $key2
     *
     * @return false|int
     */
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
        }

        return self::regexMatch($key1, '^'.$key2.'$');
    }

    /**
     * the wrapper for KeyMatch2.
     *
     * @param mixed ...$args
     *
     * @return false|int
     */
    public static function keyMatch2Func(...$args)
    {
        $name1 = $args[0];
        $name2 = $args[1];

        return self::keyMatch2($name1, $name2);
    }

    /**
     * determines whether key1 matches the pattern of key2 (similar to RESTful path), key2 can contain a *.
     * For example, "/foo/bar" matches "/foo/*", "/resource1" matches "/{resource}".
     *
     * @param string $key1
     * @param string $key2
     *
     * @return false|int
     */
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

        return self::regexMatch($key1, '^'.$key2.'$');
    }

    /**
     * the wrapper for KeyMatch3.
     *
     * @param mixed ...$args
     *
     * @return false|int
     */
    public static function keyMatch3Func(...$args)
    {
        $name1 = $args[0];
        $name2 = $args[1];

        return self::keyMatch3($name1, $name2);
    }

    /**
     * determines whether key1 matches the pattern of key2 in regular expression.
     *
     * @param string $key1
     * @param string $key2
     *
     * @return false|int
     */
    public static function regexMatch($key1, $key2)
    {
        return preg_match('~'.$key2.'~', $key1);
    }

    /**
     * the wrapper for RegexMatch.
     *
     * @param mixed ...$args
     *
     * @return false|int
     */
    public static function regexMatchFunc(...$args)
    {
        $name1 = $args[0];
        $name2 = $args[1];

        return self::regexMatch($name1, $name2);
    }

    /**
     * determines whether IP address ip1 matches the pattern of IP address ip2, ip2 can be an IP address or a CIDR pattern.
     *
     * @param string $ip1
     * @param string $ip2
     *
     * @return bool
     *
     * @throws \Exception
     */
    public static function iPMatch($ip1, $ip2)
    {
        $objIP1 = IP::parse($ip1);

        $objIP2 = Range::parse($ip2);

        return $objIP2->contains($objIP1);
    }

    /**
     * the wrapper for IPMatch.
     *
     * @param mixed ...$args
     *
     * @return bool
     *
     * @throws \Exception
     */
    public static function iPMatchFunc(...$args)
    {
        $ip1 = $args[0];
        $ip2 = $args[1];

        return self::iPMatch($ip1, $ip2);
    }

    /**
     * the factory method of the g(_, _) function.
     *
     * @param RoleManager|null $rm
     *
     * @return \Closure
     */
    public static function generateGFunction(RoleManager $rm = null)
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
