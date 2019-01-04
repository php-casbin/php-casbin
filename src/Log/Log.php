<?php

namespace Casbin\Log;

use Casbin\Log\Logger\DefaultLogger;

/**
 * Log.
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
     * setLogger sets the current logger.
     *
     * @param Logger $l
     */
    public static function setLogger(Logger $l)
    {
        self::$logger = $l;
    }

    /**
     * getLogger returns the current logger.
     *
     * @return Logger
     */
    public static function getLogger()
    {
        return self::$logger;
    }

    /**
     * logPrint prints the log.
     *
     * @param mix $v
     */
    public static function logPrint(...$v)
    {
        self::$logger->write(...$v);
    }

    /**
     * logPrintf prints the log with the format.
     *
     * @param string $format
     * @param mix    $v
     */
    public static function logPrintf($format, ...$v)
    {
        self::$logger->writef($format, ...$v);
    }
}

Log::setLogger(new DefaultLogger());
