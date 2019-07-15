<?php

namespace Casbin\Util;

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
    public static function escapeAssertion($s)
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

        return $s;
    }

    /**
     * removes the comments starting with # in the text.
     *
     * @param string $s
     *
     * @return string
     */
    public static function removeComments($s)
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
    public static function arrayToString($s)
    {
        return implode(', ', $s);
    }

    /**
     * removes any duplicated elements in a string array.
     *
     * @param array $s
     */
    public static function arrayRemoveDuplicates(&$s)
    {
        $s = array_keys(array_flip($s));
    }
}
