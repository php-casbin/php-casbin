<?php

declare(strict_types=1);

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
     * Sets the current logger.
     *
     * @param Logger $l
     */
    public static function setLogger(Logger $l): void
    {
        self::$logger = $l;
    }

    /**
     * Returns the current logger.
     *
     * @return Logger
     */
    public static function getLogger(): Logger
    {
        return self::$logger;
    }

    /**
     * Prints the log.
     *
     * @param mixed ...$v
     */
    public static function logPrint(...$v): void
    {
        self::$logger->write(...$v);
    }

    /**
     * Prints the log with the format.
     *
     * @param string $format
     * @param mixed  ...$v
     */
    public static function logPrintf(string $format, ...$v): void
    {
        self::$logger->writef($format, ...$v);
    }
}

Log::setLogger(new DefaultLogger());
