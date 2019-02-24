<?php

namespace Casbin\Model;

use Casbin\Util\BuiltinOperations;

/**
 * Class FunctionMap.
 *
 * @author techlee@qq.com
 */
class FunctionMap
{
    private $functions = [];

    /**
     * @param $name
     * @param \Closure $func
     */
    public function addFunction($name, \Closure $func)
    {
        $this->functions[$name] = $func;
    }

    /**
     * loads an initial function map.
     *
     * @return FunctionMap
     */
    public static function loadFunctionMap()
    {
        $fm = new self();

        $fm->addFunction('keyMatch', function (...$args) {
            return BuiltinOperations::keyMatchFunc(...$args);
        });
        $fm->addFunction('keyMatch2', function (...$args) {
            return BuiltinOperations::keyMatch2Func(...$args);
        });
        $fm->addFunction('regexMatch', function (...$args) {
            return BuiltinOperations::regexMatchFunc(...$args);
        });
        $fm->addFunction('ipMatch', function (...$args) {
            return BuiltinOperations::iPMatchFunc(...$args);
        });

        return $fm;
    }

    /**
     * @return array
     */
    public function getFunctions()
    {
        return $this->functions;
    }
}
