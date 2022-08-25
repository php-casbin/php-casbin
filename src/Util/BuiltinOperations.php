<?php

declare(strict_types=1);

namespace Casbin\Util;

use Casbin\Rbac\RoleManager;
use Closure;
use Exception;
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
     * Determines whether key1 matches the pattern of key2 (similar to RESTful path), key2 can contain a *.
     * For example, "/foo/bar" matches "/foo/*".
     *
     * @param string $key1
     * @param string $key2
     *
     * @return bool
     */
    public static function keyMatch(string $key1, string $key2): bool
    {
        if (false === strpos($key2, '*')) {
            return $key1 == $key2;
        }

        $needle = rtrim($key2, '*');

        return substr($key1, 0, \strlen($needle)) === (string)$needle;
    }

    /**
     * The wrapper for KeyMatch.
     *
     * @param mixed ...$args
     *
     * @return bool
     */
    public static function keyMatchFunc(...$args): bool
    {
        $name1 = $args[0];
        $name2 = $args[1];

        return self::keyMatch($name1, $name2);
    }

    /**
     * KeyGet returns the matched part
     * For example, "/foo/bar/foo" matches "/foo/*"
     * "bar/foo" will been returned
     *
     * @param string $key1
     * @param string $key2
     * @return string
     */
    public static function keyGet(string $key1, string $key2): string
    {
        $i = strpos($key2, '*');
        if ($i === false) {
            return "";
        }
        if (strlen($key1) > $i) {
            if (substr($key1, 0, $i) == substr($key2, 0, $i)) {
                return substr($key1, $i);
            }
        }
        return '';
    }

    /**
     * KeyGetFunc is the wrapper for KeyGet
     *
     * @param mixed ...$args
     * @return string
     */
    public static function keyGetFunc(...$args)
    {
        $name1 = $args[0];
        $name2 = $args[1];

        return self::keyGet($name1, $name2);
    }

    /**
     * Determines whether key1 matches the pattern of key2 (similar to RESTful path), key2 can contain a *.
     * For example, "/foo/bar" matches "/foo/*", "/resource1" matches "/:resource".
     *
     * @param string $key1
     * @param string $key2
     *
     * @return bool
     */
    public static function keyMatch2(string $key1, string $key2): bool
    {
        if ('*' === $key2) {
            $key2 = '.*';
        }
        $key2 = str_replace(['/*'], ['/.*'], $key2);

        $pattern = '/:[^\/]+/';

        $key2 = preg_replace_callback(
            $pattern,
            function ($m) {
                return '[^\/]+';
            },
            $key2
        );

        return self::regexMatch($key1, '^' . $key2 . '$');
    }

    /**
     * The wrapper for KeyMatch2.
     *
     * @param mixed ...$args
     *
     * @return bool
     */
    public static function keyMatch2Func(...$args): bool
    {
        $name1 = $args[0];
        $name2 = $args[1];

        return self::keyMatch2($name1, $name2);
    }

    /**
     * KeyGet2 returns value matched pattern
     * For example, "/resource1" matches "/:resource"
     * if the pathVar == "resource", then "resource1" will be returned
     *
     * @param string $key1
     * @param string $key2
     * @param string $pathVar
     * @return string
     */
    public static function keyGet2(string $key1, string $key2, string $pathVar): string
    {
        $key2 = str_replace(['/*'], ['/.*'], $key2);

        $pattern = '/:[^\/]+/';
        $keys = [];
        preg_match_all($pattern, $key2, $keys);
        $keys = $keys[0];
        $key2 = preg_replace_callback(
            $pattern,
            function ($m) {
                return '([^\/]+)';
            },
            $key2
        );

        $key2 = "~^" . $key2 . "$~";
        $values = [];
        preg_match($key2, $key1, $values);

        if (count($values) === 0) {
            return '';
        }
        foreach ($keys as $i => $key) {
            if ($pathVar == substr($key, 1)) {
                return $values[$i + 1];
            }
        }
        return '';
    }

    /**
     * KeyGet2Func is the wrapper for KeyGet2
     *
     * @param mixed ...$args
     * @return string
     */
    public static function keyGet2Func(...$args)
    {
        $name1 = $args[0];
        $name2 = $args[1];
        $key   = $args[2];

        return self::keyGet2($name1, $name2, $key);
    }

    /**
     * Determines whether key1 matches the pattern of key2 (similar to RESTful path), key2 can contain a *.
     * For example, "/foo/bar" matches "/foo/*", "/resource1" matches "/{resource}".
     *
     * @param string $key1
     * @param string $key2
     *
     * @return bool
     */
    public static function keyMatch3(string $key1, string $key2): bool
    {
        $key2 = str_replace(['/*'], ['/.*'], $key2);

        $pattern = '/\{[^\/]+\}/';
        $key2 = preg_replace_callback(
            $pattern,
            function ($m) {
                return '[^\/]+';
            },
            $key2
        );

        return self::regexMatch($key1, '^' . $key2 . '$');
    }

    /**
     * The wrapper for KeyMatch3.
     *
     * @param mixed ...$args
     *
     * @return bool
     */
    public static function keyMatch3Func(...$args): bool
    {
        $name1 = $args[0];
        $name2 = $args[1];

        return self::keyMatch3($name1, $name2);
    }

    /**
     * Determines whether key1 matches the pattern of key2 (similar to RESTful path), key2 can contain a *.
     * Besides what KeyMatch3 does, KeyMatch4 can also match repeated patterns:
     * "/parent/123/child/123" matches "/parent/{id}/child/{id}"
     * "/parent/123/child/456" does not match "/parent/{id}/child/{id}"
     * But KeyMatch3 will match both.
     *
     * @param string $key1
     * @param string $key2
     *
     * @return bool
     */
    public static function keyMatch4(string $key1, string $key2): bool
    {
        $key2 = str_replace(['/*'], ['/.*'], $key2);

        $tokens = [];
        $pattern = '/\{([^\/]+)\}/';
        $key2 = preg_replace_callback(
            $pattern,
            function ($m) use (&$tokens) {
                $tokens[] = $m[1];

                return '([^\/]+)';
            },
            $key2
        );

        $matched = preg_match_all('~^' . $key2 . '$~', $key1, $matches);
        if (!$matched) {
            return false;
        }

        $values = [];
        foreach ($tokens as $key => $token) {
            if (!isset($values[$token])) {
                $values[$token] = $matches[$key + 1];
            }
            if ($values[$token] != $matches[$key + 1]) {
                return false;
            }
        }

        return true;
    }

    /**
     * The wrapper for KeyMatch4.
     *
     * @param mixed ...$args
     *
     * @return bool
     */
    public static function keyMatch4Func(...$args): bool
    {
        $name1 = $args[0];
        $name2 = $args[1];

        return self::keyMatch4($name1, $name2);
    }

    /**
     * Determines whether key1 matches the pattern of key2 and ignores the parameters in key2.
     * For example, "/foo/bar?status=1&type=2" matches "/foo/bar"
     *
     * @param string $key1
     * @param string $key2
     *
     * @return bool
     */
    public static function keyMatch5(string $key1, string $key2): bool
    {
        $pos = strpos($key1, '?');
        if ($pos == false) {
            return $key1 == $key2;
        }

        return substr($key1, 0, $pos) == $key2;
    }

    /**
     * the wrapper for KeyMatch5.
     *
     * @param mixed ...$args
     *
     * @return bool
     */
    public static function keyMatch5Func(...$args): bool
    {
        $name1 = $args[0];
        $name2 = $args[1];

        return self::keyMatch5($name1, $name2);
    }

    /**
     * Determines whether key1 matches the pattern of key2 in regular expression.
     *
     * @param string $key1
     * @param string $key2
     *
     * @return bool
     */
    public static function regexMatch(string $key1, string $key2): bool
    {
        return (bool)preg_match('~' . $key2 . '~', $key1);
    }

    /**
     * The wrapper for RegexMatch.
     *
     * @param mixed ...$args
     *
     * @return bool
     */
    public static function regexMatchFunc(...$args): bool
    {
        $name1 = $args[0];
        $name2 = $args[1];

        return self::regexMatch($name1, $name2);
    }

    /**
     * Determines whether IP address ip1 matches the pattern of IP address ip2, ip2 can be an IP address or a CIDR
     * pattern.
     *
     * @param string $ip1
     * @param string $ip2
     *
     * @return bool
     *
     * @throws Exception
     */
    public static function ipMatch(string $ip1, string $ip2): bool
    {
        $objIP1 = IP::parse($ip1);

        $objIP2 = Range::parse($ip2);

        return $objIP2->contains($objIP1);
    }

    /**
     * The wrapper for IPMatch.
     *
     * @param mixed ...$args
     *
     * @return bool
     *
     * @throws Exception
     */
    public static function ipMatchFunc(...$args): bool
    {
        $ip1 = $args[0];
        $ip2 = $args[1];

        return self::ipMatch($ip1, $ip2);
    }

    /**
     * Returns true if the specified `string` matches the given glob `pattern`.
     *
     * @param string $str
     * @param string $pattern
     *
     * @return bool
     *
     * @throws Exception
     */
    public static function globMatch(string $str, string $pattern): bool
    {
        return fnmatch($pattern, $str, FNM_PATHNAME | FNM_PERIOD);
    }

    /**
     * The wrapper for globMatch.
     *
     * @param mixed ...$args
     *
     * @return bool
     *
     * @throws Exception
     */
    public static function globMatchFunc(...$args): bool
    {
        $str = $args[0];
        $pattern = $args[1];

        return self::globMatch($str, $pattern);
    }

    /**
     * The factory method of the g(_, _) function.
     *
     * @param RoleManager|null $rm
     *
     * @return Closure
     */
    public static function generateGFunction(RoleManager $rm = null): Closure
    {
        $memorized = [];
        return function (...$args) use ($rm, &$memorized) {
            $key = implode(chr(0b0), $args);

            if(isset($memorized[$key])){
                return $memorized[$key];
            }

            $name1 = $args[0];
            $name2 = $args[1];

            if (null === $rm) {
                $v = $name1 == $name2;
            } elseif (2 == \count($args)) {
                $v = $rm->hasLink($name1, $name2);
            } else {
                $domain = (string)$args[2];
                $v = $rm->hasLink($name1, $name2, $domain);
            }

            $memorized[$key] = $v;
            return $v;
        };
    }
}
