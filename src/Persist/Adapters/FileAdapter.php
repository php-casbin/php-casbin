<?php
namespace Casbin\Persist\Adapters;

use Casbin\Exceptions\CasbinException;
use Casbin\Persist\Adapter;
use Casbin\Util\Util;

/**
 *
 */
class FileAdapter implements Adapter
{
    protected $filePath;

    public function __construct($filePath)
    {
        $this->filePath = $filePath;
    }

    public function loadPolicy($model)
    {
        if (!file_exists($this->filePath)) {
            throw new CasbinException("invalid file path, file path cannot be empty");
        }

        $this->loadPolicyFile($model);
    }

    public function savePolicy($model)
    {
        if (!file_exists($this->filePath)) {
            throw new CasbinException("invalid file path, file path cannot be empty");
        }

        $writeString = '';

        foreach ($model->model['p'] as $ptype => $ast) {
            foreach ($ast->policy as $rule) {
                $writeString .= $ptype . ',';
                $writeString .= Util::arrayToString($rule);
                $writeString .= PHP_EOL;
            }
        }

        foreach ($model->model['g'] as $ptype => $ast) {
            foreach ($ast->policy as $rule) {
                $writeString .= $ptype . ',';
                $writeString .= Util::arrayToString($rule);
                $writeString .= PHP_EOL;
            }
        }

        return $this->savePolicyFile(rtrim($writeString, PHP_EOL));
    }

    public function loadPolicyFile($model)
    {
        $file = fopen($this->filePath, 'r');
        while ($line = fgets($file)) {
            $this->loadPolicyLine(trim($line), $model);
        }
        fclose($file);
    }

    public function savePolicyFile($text)
    {
        return file_put_contents($this->filePath, $text, FILE_APPEND | LOCK_EX);
    }

    public function loadPolicyLine($line, $model)
    {
        if ($line == '') {
            return;
        }

        if (substr($line, 0, 1) == '#') {
            return;
        }

        $tokens = explode(', ', $line);
        $key    = $tokens[0];
        $sec    = $key[0];

        if (!isset($model->model[$sec][$key])) {
            return;
        }
        $model->model[$sec][$key]->policy[] = array_slice($tokens, 1);
    }

    public function addPolicy($sec, $ptype, $rule)
    {
        throw new CasbinException("not implemented");
    }

    public function removePolicy($sec, $ptype, $rule)
    {
        throw new CasbinException("not implemented");
    }

    public function removeFilteredPolicy($sec, $ptype, $fieldIndex, ...$fieldValues)
    {
        throw new CasbinException("not implemented");
    }

}
