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
    public static Logger $logger;

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
     * Log model information.
     * 
     * @param array $model
     * 
     * @return void
     */
    public static function logModel(array $model): void
    {
        self::$logger->logModel($model);
    }

    /**
     * Log enforcer information.
     * 
     * @param string $matcher
     * @param array $request
     * @param bool $result
     * @param array $explains
     * 
     * @return void
     */
    public static function logEnforce(string $matcher, array $request, bool $result, array $explains): void
    {
        self::$logger->logEnforce($matcher, $request, $result, $explains);
    }

    /**
     * Log role information.
     * 
     * @param array $roles
     * 
     * @return void
     */
    public static function logRole(array $roles): void
    {
        self::$logger->logRole($roles);
    }

    /**
     * Log policy information.
     * 
     * @param array $policy
     * 
     * @return void
     */
    public static function logPolicy(array $policy): void
    {
        self::$logger->logPolicy($policy);
    }

    /**
     * Log error information.
     * 
     * @param \Exception $err
     * @param string ...$msg
     * 
     * @return void
     */
    public static function logError(\Exception $err, string ...$msg): void
    {
        self::$logger->logError($err, ...$msg);
    }
}

Log::setLogger(new DefaultLogger());
