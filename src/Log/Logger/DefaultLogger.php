<?php

declare(strict_types=1);

namespace Casbin\Log\Logger;

use Casbin\Log\Logger;
use Psr\Log\{AbstractLogger, LoggerInterface};

/**
 * Class DefaultLogger.
 *
 * @author techlee@qq.com
 * @author 1692898084@qq.com
 */
class DefaultLogger implements Logger
{
    /**
     * DefaultLogger is the implementation for a Logger using golang log.
     *
     * @var bool
     */
    public bool $enabled = false;

    /**
     * PSR-3 logger interface implementation.
     *
     * @see https://www.php-fig.org/psr/psr-3/
     * @var LoggerInterface
     */
    public LoggerInterface $psrLogger;

    /**
     * DefaultLogger constructor.
     * If a PSR-3 logger interface implementation is not given, 
     * the default implementation based on filesystem will be used.
     *
     * @param LoggerInterface|null $psrLogger The PSR-3 logger interface implementation.
     */
    public function __construct(?LoggerInterface $psrLogger = null)
    {
        if (!is_null($psrLogger)) {
            $this->psrLogger = $psrLogger;
            return;
        }
        $this->psrLogger = new class extends AbstractLogger {
            public string $path = '';

            public function __construct()
            {
                $this->path = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'casbin.log';
            }

            public function log($level, string|\Stringable $message, array $context = []): void
            {
                $timestamp = date('Y-m-d H:i:s');
                $message = (string) $message;
                foreach ($context as $key => $value) {
                    $message = str_replace("{{$key}}", (string) $value, $message);
                }
                $content = sprintf("[%s] %s: %s" . PHP_EOL, $timestamp, strtoupper($level), $message);
                file_put_contents($this->path, $content, FILE_APPEND | LOCK_EX);
            }
        };
    }

    /**
     * enableLog.
     *
     * @param bool $enable
     */
    public function enableLog(bool $enable): void
    {
        $this->enabled = $enable;
    }

    /**
     * @return bool
     */
    public function isEnabled(): bool
    {
        return $this->enabled;
    }

    /**
     * Log model information.
     * 
     * @param array $model
     * 
     * @return void
     */
    public function logModel(array $model): void
    {
        if (!$this->enabled) {
            return;
        }

        $str = '';
        foreach ($model as $v) {
            $str .= sprintf("%s " . PHP_EOL, '[' . implode(' ', $v) . ']');
        }

        $this->psrLogger->info('Model: {info}', ['info' => $str]);
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
    public function logEnforce(string $matcher, array $request, bool $result, array $explains): void
    {
        if (!$this->enabled) {
            return;
        }

        $reqStr = implode(', ', array_values($request));
        $reqStr .= sprintf(" ---> %s" . PHP_EOL, var_export($result, true));

        $hpStr = implode(', ', array_values($explains));
        if (count($explains) > 0) {
            $hpStr .= PHP_EOL;
        }

        $this->psrLogger->info('Request: {request}Hit Policy: {hitPolicy}', ['request' => $reqStr, 'hitPolicy' => $hpStr]);
    }

    /**
     * Log policy information.
     * 
     * @param array $policy
     * 
     * @return void
     */
    public function logPolicy(array $policy): void
    {
        if (!$this->enabled) {
            return;
        }

        $str = '';
        foreach ($policy as $ptype => $ast) {
            $str .= $ptype . ' : [';
            foreach ($ast as $rule) {
                $str .= '[' . implode(' ', $rule) . '] ';
            }
            $str .= PHP_EOL;
        }
        if ($str !== '') {
            $str = rtrim($str) . ']';
        }

        $this->psrLogger->info('Policy: {policy}', ['policy' => $str]);
    }

    /**
     * Log role information.
     * 
     * @param array $roles
     * 
     * @return void
     */
    public function logRole(array $roles): void
    {
        if (!$this->enabled) {
            return;
        }

        $this->psrLogger->info('Roles: {roles}', ['roles' => implode(', ', $roles)]);
    }

    /**
     * Log error information.
     * 
     * @param \Exception $err
     * @param string ...$msg
     * 
     * @return void
     */
    public function logError(\Exception $err, string ...$msg): void
    {
        if (!$this->enabled) {
            return;
        }

        $errStr = $err->getMessage();

        if (!empty($msg)) {
            $errStr .= ' ' . implode(' ', $msg);
        }

        $this->psrLogger->error($errStr);
    }
}
