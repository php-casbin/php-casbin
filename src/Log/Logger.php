<?php

namespace Casbin\Log;

/**
 * Interface Logger.
 *
 * @author techlee@qq.com
 */
interface Logger
{
    /**
     * controls whether print the message.
     *
     * @param bool $enable
     */
    public function enableLog($enable);

    /**
     * returns if logger is enabled.
     *
     * @return bool
     */
    public function isEnabled();

    /**
     * formats using the default formats for its operands and logs the message.
     *
     * @param mixed ...$v
     *
     * @return mixed
     */
    public function write(...$v);

    /**
     * formats according to a format specifier and logs the message.
     *
     * @param $format
     * @param mixed ...$v
     *
     * @return mixed
     */
    public function writef($format, ...$v);
}
