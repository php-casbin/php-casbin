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
use Casbin\Persist\UpdatableAdapter;
use Casbin\Util\Util;

/**
 * Class FileAdapter
 * The file adapter for Casbin.
 * It can load policy from file or save policy to file.
 *
 * @author techlee@qq.com
 */
class FileAdapter implements Adapter, BatchAdapter, UpdatableAdapter
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
     * Loads all policy rules from the storage.
     *
     * @param Model $model
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
     * Saves all policy rules to the storage.
     *
     * @param Model $model
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
                    $writeString .= $ptype . ', ';
                    $writeString .= Util::arrayToString($rule);
                    $writeString .= PHP_EOL;
                }
            }
        }

        if (isset($model['g'])) {
            foreach ($model['g'] as $ptype => $ast) {
                foreach ($ast->policy as $rule) {
                    $writeString .= $ptype . ', ';
                    $writeString .= Util::arrayToString($rule);
                    $writeString .= PHP_EOL;
                }
            }
        }

        $this->savePolicyFile(rtrim($writeString, PHP_EOL));
    }

    /**
     * @param Model $model
     * @throws InvalidFilePathException
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
     * Adds a policy rule to the storage.
     *
     * @param string $sec
     * @param string $ptype
     * @param string[] $rule
     *
     * @throws NotImplementedException
     */
    public function addPolicy(string $sec, string $ptype, array $rule): void
    {
        throw new NotImplementedException('not implemented');
    }

    /**
     * Adds a policy rule to the storage.
     *
     * @param string $sec
     * @param string $ptype
     * @param string[][] $rules
     *
     * @throws NotImplementedException
     */
    public function addPolicies(string $sec, string $ptype, array $rules): void
    {
        throw new NotImplementedException('not implemented');
    }

    /**
     * Removes a policy rule from the storage.
     *
     * @param string $sec
     * @param string $ptype
     * @param string[] $rule
     *
     * @throws NotImplementedException
     */
    public function removePolicy(string $sec, string $ptype, array $rule): void
    {
        throw new NotImplementedException('not implemented');
    }

    /**
     * Removes a policy rules from the storage.
     *
     * @param string $sec
     * @param string $ptype
     * @param string[][] $rules
     *
     * @throws NotImplementedException
     */
    public function removePolicies(string $sec, string $ptype, array $rules): void
    {
        throw new NotImplementedException('not implemented');
    }

    /**
     * Removes policy rules that match the filter from the storage.
     *
     * @param string $sec
     * @param string $ptype
     * @param int $fieldIndex
     * @param string ...$fieldValues
     *
     * @throws NotImplementedException
     */
    public function removeFilteredPolicy(string $sec, string $ptype, int $fieldIndex, string ...$fieldValues): void
    {
        throw new NotImplementedException('not implemented');
    }

    /**
     * Updates a policy rule from storage.
     * This is part of the Auto-Save feature.
     *
     * @param string $sec
     * @param string $ptype
     * @param string[] $oldRule
     * @param string[] $newPolicy
     */
    public function updatePolicy(string $sec, string $ptype, array $oldRule, array $newPolicy): void
    {
        throw new NotImplementedException('not implemented');
    }

    /**
     * UpdatePolicies updates some policy rules to storage, like db, redis.
     *
     * @param string $sec
     * @param string $ptype
     * @param string[][] $oldRules
     * @param string[][] $newRules
     * @return void
     */
    public function updatePolicies(string $sec, string $ptype, array $oldRules, array $newRules): void
    {
        throw new NotImplementedException('not implemented');
    }

    /**
     * UpdateFilteredPolicies deletes old rules and adds new rules.
     *
     * @param string $sec
     * @param string $ptype
     * @param array $newPolicies
     * @param integer $fieldIndex
     * @param string ...$fieldValues
     * @return array
     */
    public function updateFilteredPolicies(string $sec, string $ptype, array $newPolicies, int $fieldIndex, string ...$fieldValues): array
    {
        throw new NotImplementedException('not implemented');
    }
}
