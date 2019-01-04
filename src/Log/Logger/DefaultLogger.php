<?php

namespace Casbin\Log\Logger;

use Casbin\Log\Logger;

/**
 * DefaultLogger.
 */
class DefaultLogger implements Logger
{
    /**
     * DefaultLogger is the implementation for a Logger using golang log.
     *
     * @var bool
     */
    public $enable = false;

    public $name = 'casbin.log';

    public $path = '/tmp';

    public function __construct()
    {
        $this->path = sys_get_temp_dir();
    }

    /**
     * enableLog.
     *
     * @param bool $enable
     */
    public function enableLog($enable)
    {
        $this->enable = $enable;
    }

    public function isEnabled()
    {
        return $this->enable;
    }

    public function print(...$v)
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
            $this->write($content);
        }
    }

    public function printf($format, ...$v)
    {
        if ($this->enable) {
            $content = date('Y-m-d H:i:s ');
            $content .= sprintf($format, ...$v);
            $content .= PHP_EOL;
            $this->write($content);
        }
    }

    public function write($content)
    {
        $file = $this->path.DIRECTORY_SEPARATOR.$this->name;
        file_put_contents($file, $content, FILE_APPEND | LOCK_EX);
    }
}
