<?php

declare(strict_types=1);

namespace Casbin\Persist\Adapters;

use Casbin\Exceptions\CasbinException;
use Casbin\Exceptions\InvalidFilePathException;
use Casbin\Exceptions\NotImplementedException;
use Casbin\Model\Model;
use Casbin\Persist\Adapter;
use Casbin\Persist\AdapterHelper;
use Casbin\Persist\BatchAdapter;
use Casbin\Util\Util;

/**
 * Class FileAdapter
 * the file adapter for Casbin.
 * it can load policy from file or save policy to file.
 *
 * @author techlee@qq.com
 */
class FileAdapter implements Adapter, BatchAdapter
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
    public function __construct(string $filePath)
    {
        $this->filePath = $filePath;
    }

    /**
     * loads all policy rules from the storage.
     *
     * @param \Casbin\Model\Model $model
     *
     * @throws CasbinException
     */
    public function loadPolicy(Model $model): void
    {
        if (!file_exists($this->filePath)) {
            throw new InvalidFilePathException('invalid file path, file path cannot be empty');
        }

        $this->loadPolicyFile($model);
    }

    /**
     * saves all policy rules to the storage.
     *
     * @param \Casbin\Model\Model $model
     *
     * @throws CasbinException
     */
    public function savePolicy(Model $model): void
    {
        if ('' == $this->filePath) {
            throw new InvalidFilePathException('invalid file path, file path cannot be empty');
        }

        $writeString = '';

        if (isset($model['p'])) {
            foreach ($model['p'] as $ptype => $ast) {
                foreach ($ast->policy as $rule) {
                    $writeString .= $ptype.', ';
                    $writeString .= Util::arrayToString($rule);
                    $writeString .= PHP_EOL;
                }
            }
        }

        if (isset($model['g'])) {
            foreach ($model['g'] as $ptype => $ast) {
                foreach ($ast->policy as $rule) {
                    $writeString .= $ptype.', ';
                    $writeString .= Util::arrayToString($rule);
                    $writeString .= PHP_EOL;
                }
            }
        }

        $this->savePolicyFile(rtrim($writeString, PHP_EOL));
    }

    /**
     * @param \Casbin\Model\Model $model
     */
    protected function loadPolicyFile(Model $model): void
    {
        $file = fopen($this->filePath, 'rb');

        if (false === $file) {
            throw new InvalidFilePathException(sprintf('Unable to access to the specified path "%s"', $this->filePath));
        }

        while ($line = fgets($file)) {
            $this->loadPolicyLine(trim($line), $model);
        }
        fclose($file);
    }

    /**
     * @param string $text
     */
    protected function savePolicyFile(string $text): void
    {
        file_put_contents($this->filePath, $text, LOCK_EX);
    }

    /**
     * adds a policy rule to the storage.
     *
     * @param string $sec
     * @param string $ptype
     * @param array  $rule
     *
     * @throws NotImplementedException
     */
    public function addPolicy(string $sec, string $ptype, array $rule): void
    {
        throw new NotImplementedException('not implemented');
    }

    /**
     * adds a policy rule to the storage.
     *
     * @param string $sec
     * @param string $ptype
     * @param array  $rules
     *
     * @throws NotImplementedException
     */
    public function addPolicies(string $sec, string $ptype, array $rules): void
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
     * @throws NotImplementedException
     */
    public function removePolicy(string $sec, string $ptype, array $rule): void
    {
        throw new NotImplementedException('not implemented');
    }

    /**
     * removes a policy rules from the storage.
     *
     * @param string $sec
     * @param string $ptype
     * @param array  $rules
     *
     * @throws NotImplementedException
     */
    public function removePolicies(string $sec, string $ptype, array $rules): void
    {
        throw new NotImplementedException('not implemented');
    }

    /**
     * removes policy rules that match the filter from the storage.
     *
     * @param string $sec
     * @param string $ptype
     * @param int    $fieldIndex
     * @param string ...$fieldValues
     *
     * @throws NotImplementedException
     */
    public function removeFilteredPolicy(string $sec, string $ptype, int $fieldIndex, string ...$fieldValues): void
    {
        throw new NotImplementedException('not implemented');
    }
}
