<?php

namespace Casbin\Persist\Adapters;

use Casbin\Exceptions\CasbinException;
use Casbin\Exceptions\NotImplementedException;
use Casbin\Persist\Adapter;
use Casbin\Persist\AdapterHelper;
use Casbin\Util\Util;

/**
 * Class FileAdapter
 * the file adapter for Casbin.
 * it can load policy from file or save policy to file.
 *
 * @author techlee@qq.com
 */
class FileAdapter implements Adapter
{
    use AdapterHelper;

    /**
     * @var string
     */
    protected $filePath;

    /**
     * FileAdapter constructor.
     *
     * @param string $filePath
     */
    public function __construct($filePath)
    {
        $this->filePath = $filePath;
    }

    /**
     * loads all policy rules from the storage.
     *
     * @param \Casbin\Model\Model $model
     *
     * @return mixed|void
     *
     * @throws CasbinException
     */
    public function loadPolicy($model)
    {
        if (!file_exists($this->filePath)) {
            throw new CasbinException('invalid file path, file path cannot be empty');
        }

        $this->loadPolicyFile($model);
    }

    /**
     * saves all policy rules to the storage.
     *
     * @param \Casbin\Model\Model $model
     *
     * @return bool|int
     *
     * @throws CasbinException
     */
    public function savePolicy($model)
    {
        if ('' == $this->filePath) {
            throw new CasbinException('invalid file path, file path cannot be empty');
        }

        $writeString = '';

        if (isset($model->model['p'])) {
            foreach ($model->model['p'] as $ptype => $ast) {
                foreach ($ast->policy as $rule) {
                    $writeString .= $ptype.', ';
                    $writeString .= Util::arrayToString($rule);
                    $writeString .= PHP_EOL;
                }
            }
        }

        if (isset($model->model['g'])) {
            foreach ($model->model['g'] as $ptype => $ast) {
                foreach ($ast->policy as $rule) {
                    $writeString .= $ptype.', ';
                    $writeString .= Util::arrayToString($rule);
                    $writeString .= PHP_EOL;
                }
            }
        }

        return $this->savePolicyFile(rtrim($writeString, PHP_EOL));
    }

    /**
     * @param \Casbin\Model\Model $model
     */
    public function loadPolicyFile($model)
    {
        $file = fopen($this->filePath, 'rb');
        while ($line = fgets($file)) {
            $this->loadPolicyLine(trim($line), $model);
        }
        fclose($file);
    }

    /**
     * @param string $text
     *
     * @return bool|int
     */
    public function savePolicyFile($text)
    {
        return file_put_contents($this->filePath, $text, LOCK_EX);
    }

    /**
     * adds a policy rule to the storage.
     *
     * @param string $sec
     * @param string $ptype
     * @param array  $rule
     *
     * @return mixed|void
     *
     * @throws NotImplementedException
     */
    public function addPolicy($sec, $ptype, $rule)
    {
        throw new NotImplementedException('not implemented');
    }

    /**
     * removes a policy rule from the storage.
     *
     * @param string $sec
     * @param string $ptype
     * @param array  $rule
     *
     * @return mixed|void
     *
     * @throws NotImplementedException
     */
    public function removePolicy($sec, $ptype, $rule)
    {
        throw new NotImplementedException('not implemented');
    }

    /**
     * removes policy rules that match the filter from the storage.
     *
     * @param string $sec
     * @param string $ptype
     * @param int    $fieldIndex
     * @param mixed  ...$fieldValues
     *
     * @return mixed|void
     *
     * @throws NotImplementedException
     */
    public function removeFilteredPolicy($sec, $ptype, $fieldIndex, ...$fieldValues)
    {
        throw new NotImplementedException('not implemented');
    }
}
