<?php
namespace Casbin\Util;

/**
 * Log
 * @author techlee@qq.com
 */
class Log
{
    public static $enableLog = false;

    public static function logPrint(...$v)
    {
        if (self::$enableLog) {
            echo date('Y-m-d H:i:s ');
            foreach ($v as $value) {
                if (is_array($value)) {
                    $value = json_encode($value);
                } elseif (is_object($value)) {
                    $value = json_encode($value);
                }
                echo $value;
            }
            echo PHP_EOL;
        }
    }

    public static function logPrintf($format, ...$v)
    {
        if (self::$enableLog) {
            echo date('Y-m-d H:i:s ');
            printf($format, ...$v);
            echo PHP_EOL;
        }
    }
}
