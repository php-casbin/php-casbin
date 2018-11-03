<?php

namespace Casbin\Persist;

/**
 * Watcher.
 *
 * @author techlee@qq.com
 */
interface Watcher
{
    public function setUpdateCallback($func);

    public function update();
}
