<?php

namespace Casbin\Log;

use Casbin\Log\Logger\DefaultLogger;

/**
 * Class Log.
 *
 * @author techlee@qq.com
 */
class Log
{
    /**
     * $logger.
     *
     * @var Logger
     */
    public static $logger;

    /**
     * sets the current logger.
     *
     * @param Logger $l
     */
    public static function setLogger(Logger $l)
    {
        self::$logger = $l;
    }

    /**
     * returns the current logger.
     *
     * @return Logger
     */
    public static function getLogger()
    {
        return self::$logger;
    }

    /**
     * prints the log.
     *
     * @param mix ...$v
     */
    public static function logPrint(...$v)
    {
        self::$logger->write(...$v);
    }

    /**
     * prints the log with the format.
     *
     * @param $format
     * @param mixed ...$v
     */
    public static function logPrintf($format, ...$v)
    {
        self::$logger->writef($format, ...$v);
    }
}

Log::setLogger(new DefaultLogger());
