<?php

declare(strict_types=1);

namespace Casbin\Log\Logger;

use Casbin\Log\Logger;

/**
 * Class DefaultLogger.
 *
 * @author techlee@qq.com
 */
class DefaultLogger implements Logger
{
    /**
     * DefaultLogger is the implementation for a Logger using golang log.
     *
     * @var bool
     */
    public $enable = false;

    /**
     * @var string
     */
    public $name = 'casbin.log';

    /**
     * @var string
     */
    public $path = '/tmp';

    /**
     * DefaultLogger constructor.
     */
    public function __construct()
    {
        $this->path = sys_get_temp_dir();
    }

    /**
     * enableLog.
     *
     * @param bool $enable
     */
    public function enableLog(bool $enable): void
    {
        $this->enable = $enable;
    }

    /**
     * @return bool
     */
    public function isEnabled(): bool
    {
        return $this->enable;
    }

    /**
     * @param mixed ...$v
     */
    public function write(...$v): void
    {
        if ($this->enable) {
            $content = date('Y-m-d H:i:s ');
            foreach ($v as $value) {
                if (\is_array($value)) {
                    $value = json_encode($value);
                } elseif (\is_object($value)) {
                    $value = json_encode($value);
                }
                $content .= $value;
            }
            $content .= PHP_EOL;
            $this->save($content);
        }
    }

    /**
     * @param string $format
     * @param mixed  ...$v
     */
    public function writef(string $format, ...$v): void
    {
        if ($this->enable) {
            $content = date('Y-m-d H:i:s ');
            $content .= sprintf($format, ...$v);
            $content .= PHP_EOL;
            $this->save($content);
        }
    }

    /**
     * @param string $content
     */
    public function save(string $content): void
    {
        $file = $this->path.DIRECTORY_SEPARATOR.$this->name;
        file_put_contents($file, $content, FILE_APPEND | LOCK_EX);
    }
}
