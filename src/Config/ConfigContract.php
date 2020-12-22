<?php

declare(strict_types=1);

namespace Casbin\Config;

use Casbin\Exceptions\CasbinException;

/**
 * ConfigContract defines the behavior of a Config implementation.
 *
 * @author techlee@qq.com
 */
interface ConfigContract
{
    /**
     * lookups up the value using the provided key and converts the value to a string.
     *
     * @param string $key
     *
     * @return string
     */
    public function getString(string $key): string;

    /**
     * lookups up the value using the provided key and converts the value to an array of string
     * by splitting the string by comma.
     *
     * @param string $key
     *
     * @return array
     */
    public function getStrings(string $key): array;

    /**
     * sets the value for the specific key in the Config.
     *
     * @param string $key
     * @param string $value
     *
     * @throws CasbinException
     */
    public function set(string $key, string $value): void;

    /**
     * section.key or key.
     *
     * @param string $key
     *
     * @return string
     */
    public function get(string $key): string;
}
