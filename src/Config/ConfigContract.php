<?php

namespace Casbin\Config;

/**
 * Interface ConfigContract.
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
    public function getString($key);

    /**
     * lookups up the value using the provided key and converts the value to an array of string
     * by splitting the string by comma.
     *
     * @param string $key
     *
     * @return array
     */
    public function getStrings($key);

    /**
     * sets the value for the specific key in the Config.
     *
     * @param string $key
     * @param string $value
     *
     * @throws CasbinException
     */
    public function set($key, $value);

    /**
     * section.key or key.
     *
     * @param string $key
     *
     * @return string
     */
    public function get($key);
}
