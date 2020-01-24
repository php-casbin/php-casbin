<?php

declare(strict_types=1);

namespace Casbin\Util;

use Casbin\Exceptions\CasbinException;

/**
 * Class Util.
 *
 * @author techlee@qq.com
 */
class Util
{
    /**
     * escapes the dots in the assertion, because the expression evaluation doesn't support such variable names.
     *
     * @param string $s
     *
     * @return string
     */
    public static function escapeAssertion(string $s): string
    {
        if (0 === strpos($s, 'r.')) {
            $s = substr_replace($s, 'r_', 0, 2);
        }
        if (0 === strpos($s, 'p.')) {
            $s = substr_replace($s, 'p_', 0, 2);
        }

        $s = preg_replace_callback("~(\|| |=|\)|\(|&|<|>|,|\+|-|!|\*|\/)(r|p)(\.)~", function ($m) {
            return $m[1].$m[2].'_';
        }, $s);

        if (null === $s) {
            throw new CasbinException(sprintf('Unable to escape assertion "%s"', $s));
        }

        return $s;
    }

    /**
     * removes the comments starting with # in the text.
     *
     * @param string $s
     *
     * @return string
     */
    public static function removeComments(string $s): string
    {
        $pos = strpos($s, '#');

        return false === $pos ? $s : trim(substr($s, 0, $pos));
    }

    /**
     * gets a printable string for a string array.
     *
     * @param array $s
     *
     * @return string
     */
    public static function arrayToString(array $s): string
    {
        return implode(', ', $s);
    }

    /**
     * removes any duplicated elements in a string array.
     *
     * @param array $s
     */
    public static function arrayRemoveDuplicates(array &$s): void
    {
        $s = array_keys(array_flip($s));
    }
}
