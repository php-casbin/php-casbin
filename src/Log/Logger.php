<?php

declare(strict_types=1);

namespace Casbin\Log;

/**
 * Interface Logger.
 *
 * @author techlee@qq.com
 */
interface Logger
{
    /**
     * Controls whether print the message.
     *
     * @param bool $enable
     */
    public function enableLog(bool $enable): void;

    /**
     * Returns if logger is enabled.
     *
     * @return bool
     */
    public function isEnabled(): bool;

    /**
     * Log model information.
     *
     * @param array $model
     * 
     * @return void
     */
    public function logModel(array $model): void;

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
    public function logEnforce(string $matcher, array $request, bool $result, array $explains): void;

    /**
     * Log role information.
     *
     * @param array $roles
     * 
     * @return void
     */
    public function logRole(array $roles): void;

    /**
     * Log policy information.
     *
     * @param array $policy
     * 
     * @return void
     */
    public function logPolicy(array $policy): void;

    /**
     * Log error information.
     *
     * @param \Exception $err
     * @param string ...$message
     * 
     * @return void
     */
    public function logError(\Exception $err, string ...$message): void;
}
