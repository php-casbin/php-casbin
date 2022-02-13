<?php

declare(strict_types=1);

namespace Casbin;

use Casbin\Effector\DefaultEffector;
use Casbin\Effector\Effector;
use Casbin\Exceptions\CasbinException;
use Casbin\Exceptions\EvalFunctionException;
use Casbin\Exceptions\InvalidFilePathException;
use Casbin\Log\Log;
use Casbin\Model\FunctionMap;
use Casbin\Model\Model;
use Casbin\Persist\Adapter;
use Casbin\Persist\Adapters\FileAdapter;
use Casbin\Persist\FilteredAdapter;
use Casbin\Persist\Watcher;
use Casbin\Persist\WatcherEx;
use Casbin\Rbac\DefaultRoleManager\RoleManager as DefaultRoleManager;
use Casbin\Rbac\RoleManager;
use Casbin\Util\BuiltinOperations;
use Casbin\Util\Util;
use Symfony\Component\ExpressionLanguage\ExpressionLanguage;
use Symfony\Component\ExpressionLanguage\ParsedExpression;

/**
 * Class CoreEnforcer
 * The main interface for authorization enforcement and policy management.
 *
 * @author techlee@qq.com
 */
class CoreEnforcer
{
    /**
     * Model path.
     *
     * @var string
     */
    protected $modelPath;

    /**
     * Model.
     *
     * @var Model
     */
    protected $model;

    /**
     * FunctionMap.
     *
     * @var FunctionMap
     */
    protected $fm;

    /**
     * Effector.
     *
     * @var Effector
     */
    protected $eft;

    /**
     * Adapter.
     *
     * @var Adapter|null
     */
    protected $adapter;

    /**
     * Watcher.
     *
     * @var Watcher|null
     */
    protected $watcher;

    /**
     * RmMap.
     *
     * @var RoleManager[]
     */
    protected $rmMap;

    /**
     * $enabled.
     *
     * @var bool
     */
    protected $enabled;

    /**
     * $autoSave.
     *
     * @var bool
     */
    protected $autoSave;

    /**
     * $autoBuildRoleLinks.
     *
     * @var bool
     */
    protected $autoBuildRoleLinks;

    /**
     * $autoNotifyWatcher.
     *
     * @var bool
     */
    protected $autoNotifyWatcher;

    /**
     * Enforcer constructor.
     * Creates an enforcer via file or DB.
     * File:
     * $e = new Enforcer("path/to/basic_model.conf", "path/to/basic_policy.csv")
     * MySQL DB:
     * $a = DatabaseAdapter::newAdapter([
     *      'type'     => 'mysql', // mysql,pgsql,sqlite,sqlsrv
     *      'hostname' => '127.0.0.1',
     *      'database' => 'test',
     *      'username' => 'root',
     *      'password' => '123456',
     *      'hostport' => '3306',
     *  ]);
     * $e = new Enforcer("path/to/basic_model.conf", $a).
     *
     * @param mixed ...$params
     *
     * @throws CasbinException
     */
    public function __construct(...$params)
    {
        $parsedParamLen = 0;
        $paramLen = \count($params);
        if ($paramLen >= 1) {
            if (\is_bool($enableLog = $params[$paramLen - 1])) {
                $this->enableLog($enableLog);
                ++$parsedParamLen;
            }
        }

        if (2 == $paramLen - $parsedParamLen) {
            $p0 = $params[0];
            if (\is_string($p0)) {
                $p1 = $params[1];
                if (\is_string($p1)) {
                    $this->initWithFile($p0, $p1);
                } else {
                    $this->initWithAdapter($p0, $p1);
                }
            } else {
                if (\is_string($params[1])) {
                    throw new CasbinException('Invalid parameters for enforcer.');
                } else {
                    $this->initWithModelAndAdapter($p0, $params[1]);
                }
            }
        } elseif (1 == $paramLen - $parsedParamLen) {
            $p0 = $params[0];
            if (\is_string($p0)) {
                $this->initWithFile($p0, '');
            } else {
                $this->initWithModelAndAdapter($p0, null);
            }
        } elseif (0 == $paramLen - $parsedParamLen) {
            // pass
        } else {
            throw new CasbinException('Invalid parameters for enforcer.');
        }
    }

    /**
     * Initializes an enforcer with a model file and a policy file.
     *
     * @param string $modelPath
     * @param string $policyPath
     *
     * @throws CasbinException
     */
    public function initWithFile(string $modelPath, string $policyPath): void
    {
        $adapter = new FileAdapter($policyPath);
        $this->initWithAdapter($modelPath, $adapter);
    }

    /**
     * Initializes an enforcer with a database adapter.
     *
     * @param string $modelPath
     * @param Adapter $adapter
     *
     * @throws CasbinException
     */
    public function initWithAdapter(string $modelPath, Adapter $adapter): void
    {
        $m = Model::newModelFromFile($modelPath);
        $this->initWithModelAndAdapter($m, $adapter);

        $this->modelPath = $modelPath;
    }

    /**
     * InitWithModelAndAdapter initializes an enforcer with a model and a database adapter.
     *
     * @param Model $m
     * @param Adapter|null $adapter
     */
    public function initWithModelAndAdapter(Model $m, Adapter $adapter = null): void
    {
        $this->adapter = $adapter;
        $this->model = $m;
        $this->model->printModel();

        $this->fm = Model::loadFunctionMap();

        $this->initialize();

        // Do not initialize the full policy when using a filtered adapter
        $ok = $this->adapter instanceof FilteredAdapter ? $this->adapter->isFiltered() : false;

        if (!\is_null($this->adapter) && !$ok) {
            $this->loadPolicy();
        }
    }

    /**
     * Initializes an enforcer with a database adapter.
     */
    protected function initialize(): void
    {
        $this->rmMap = [];
        $this->eft = new DefaultEffector();
        $this->watcher = null;

        $this->enabled = true;
        $this->autoSave = true;
        $this->autoBuildRoleLinks = true;
        $this->autoNotifyWatcher = true;
        $this->initRmMap();
    }

    /**
     * Reloads the model from the model CONF file.
     * Because the policy is attached to a model, so the policy is invalidated and needs to be reloaded by calling LoadPolicy().
     *
     * @throws CasbinException
     */
    public function loadModel(): void
    {
        $this->model = Model::newModelFromFile($this->modelPath);
        $this->model->printModel();
        $this->fm = Model::loadFunctionMap();

        $this->initialize();
    }

    /**
     * Gets the current model.
     *
     * @return Model
     */
    public function getModel(): Model
    {
        return $this->model;
    }

    /**
     * Sets the current model.
     *
     * @param Model $model
     */
    public function setModel(Model $model): void
    {
        $this->model = $model;
        $this->fm = $this->model->loadFunctionMap();

        $this->initialize();
    }

    /**
     * Gets the current adapter.
     *
     * @return Adapter|null
     */
    public function getAdapter(): ?Adapter
    {
        return $this->adapter;
    }

    /**
     * Sets the current adapter.
     *
     * @param Adapter $adapter
     */
    public function setAdapter(Adapter $adapter): void
    {
        $this->adapter = $adapter;
    }

    /**
     * Sets the current watcher.
     *
     * @param Watcher $watcher
     */
    public function setWatcher(Watcher $watcher): void
    {
        $this->watcher = $watcher;
        $this->watcher->setUpdateCallback(function () {
            $this->loadPolicy();
        });
    }

    /**
     * Gets the current role manager.
     *
     * @return RoleManager
     */
    public function getRoleManager(): RoleManager
    {
        return $this->rmMap['g'];
    }

    /**
     * Gets the current role manager.
     *
     * @param RoleManager $rm
     */
    public function setRoleManager(RoleManager $rm): void
    {
        $this->rmMap['g'] = $rm;
    }

    /**
     * Sets the current effector.
     *
     * @param Effector $eft
     */
    public function setEffector(Effector $eft): void
    {
        $this->eft = $eft;
    }

    /**
     * Clears all policy.
     */
    public function clearPolicy(): void
    {
        $this->model->clearPolicy();
    }

    /**
     * Reloads the policy from file/database.
     */
    public function loadPolicy(): void
    {
        $flag = false;
        $needToRebuild = false;
        $newModel = clone $this->model;
        $newModel->clearPolicy();

        try {
            $this->adapter->loadPolicy($newModel);
            $newModel->printPolicy();
            $newModel->sortPoliciesBySubjectHierarchy();
            $newModel->sortPoliciesByPriority();

            if ($this->autoBuildRoleLinks) {
                $needToRebuild = true;
                foreach ($this->rmMap as $rm) {
                    $rm->clear();
                }
                $newModel->buildRoleLinks($this->rmMap);
            }
            $this->model = $newModel;
        } catch (InvalidFilePathException $e) {
            // Ignore throw $e;
        } catch (\Throwable $e) {
            $flag = true;
            throw $e;
        } finally {
            if ($flag) {
                if ($this->autoBuildRoleLinks && $needToRebuild) {
                    $this->buildRoleLinks();
                }
            }
        }
    }

    /**
     * Reloads a filtered policy from file/database.
     *
     * @param mixed $filter
     *
     * @throws CasbinException
     */
    public function _loadFilteredPolicy($filter): void
    {
        if ($this->adapter instanceof FilteredAdapter) {
            $filteredAdapter = $this->adapter;
            $filteredAdapter->loadFilteredPolicy($this->model, $filter);
        } else {
            throw new CasbinException('filtered policies are not supported by this adapter');
        }

        $this->model->sortPoliciesByPriority();
        $this->initRmMap();
        $this->model->printPolicy();
        if ($this->autoBuildRoleLinks) {
            $this->buildRoleLinks();
        }
    }

    /**
     * Reloads a filtered policy from file/database.
     *
     * @param mixed $filter
     *
     * @throws CasbinException
     */
    public function loadFilteredPolicy($filter): void
    {
        $this->model->clearPolicy();

        $this->_loadFilteredPolicy($filter);
    }

    /**
     * LoadIncrementalFilteredPolicy append a filtered policy from file/database.
     *
     * @param mixed $filter
     * @return void
     */
    public function loadIncrementalFilteredPolicy($filter): void
    {
        $this->_loadFilteredPolicy($filter);
    }

    /**
     * Returns true if the loaded policy has been filtered.
     *
     * @return bool
     */
    public function isFiltered(): bool
    {
        if (!$this->adapter instanceof FilteredAdapter) {
            return false;
        }

        $filteredAdapter = $this->adapter;

        return $filteredAdapter->isFiltered();
    }

    /**
     * Saves the current policy (usually after changed with Casbin API) back to file/database.
     *
     * @throws CasbinException
     */
    public function savePolicy(): void
    {
        if ($this->isFiltered()) {
            throw new CasbinException('cannot save a filtered policy');
        }

        $this->adapter->savePolicy($this->model);

        if ($this->watcher !== null && $this->autoNotifyWatcher) {
            if ($this->watcher instanceof WatcherEx) {
                $this->watcher->updateForSavePolicy($this->model);
            } else {
                $this->watcher->update();
            }
        }
    }

    /**
     * initRmMap initializes rmMap.
     *
     * @return void
     */
    public function initRmMap(): void
    {
        if (isset($this->model['g'])) {
            foreach ($this->model['g'] as $ptype => $value) {
                if (isset($this->rmMap[$ptype])) {
                    $rm = $this->rmMap[$ptype];
                    $rm->clear();
                } else {
                    $this->rmMap[$ptype] = new DefaultRoleManager(10);
                }
            }
        }
    }

    /**
     * Changes the enforcing state of Casbin, when Casbin is disabled, all access will be allowed by the Enforce() function.
     *
     * @param bool $enabled
     */
    public function enableEnforce(bool $enabled = true): void
    {
        $this->enabled = $enabled;
    }

    /**
     * Changes whether Casbin will log messages to the Logger.
     *
     * @param bool $enabled
     */
    public function enableLog(bool $enabled = true): void
    {
        Log::getLogger()->enableLog($enabled);
    }

    /**
     * Controls whether to save a policy rule automatically notify the Watcher when it is added or removed.
     *
     * @param bool $enabled
     */
    public function enableAutoNotifyWatcher(bool $enabled = true): void
    {
        $this->autoNotifyWatcher = $enabled;
    }

    /**
     * Controls whether to save a policy rule automatically to the adapter when it is added or removed.
     *
     * @param bool $autoSave
     */
    public function enableAutoSave(bool $autoSave = true): void
    {
        $this->autoSave = $autoSave;
    }

    /**
     * Controls whether to rebuild the role inheritance relations when a role is added or deleted.
     *
     * @param bool $autoBuildRoleLinks
     */
    public function enableAutoBuildRoleLinks(bool $autoBuildRoleLinks = true): void
    {
        $this->autoBuildRoleLinks = $autoBuildRoleLinks;
    }

    /**
     * Manually rebuild the role inheritance relations.
     */
    public function buildRoleLinks(): void
    {
        foreach ($this->rmMap as $rm) {
            $rm->clear();
        }

        $this->model->buildRoleLinks($this->rmMap);
    }

    /**
     * Use a custom matcher to decides whether a "subject" can access a "object" with the operation "action",
     * input parameters are usually: (matcher, sub, obj, act), use model matcher by default when matcher is "".
     *
     * @param string $matcher
     * @param array $explains
     * @param mixed ...$rvals
     *
     * @return bool
     *
     * @throws CasbinException
     */
    protected function enforcing(string $matcher, &$explains = [], ...$rvals): bool
    {
        if (!$this->enabled) {
            return true;
        }

        $functions = $this->fm->getFunctions();

        if (isset($this->model['g'])) {
            foreach ($this->model['g'] as $key => $ast) {
                $rm = $ast->rm;
                $functions[$key] = BuiltinOperations::generateGFunction($rm);
            }
        }

        if (!isset($this->model['m']['m'])) {
            throw new CasbinException('model is undefined');
        }

        $rType = "r";
        $pType = "p";
        $eType = "e";
        $mType = "m";

        switch (true) {
            case $rvals[0] instanceof EnforceContext:
                $enforceContext = $rvals[0];
                $rType = $enforceContext->rType;
                $pType = $enforceContext->pType;
                $eType = $enforceContext->eType;
                $mType = $enforceContext->mType;
                array_shift($rvals);
                break;
            default:
                break;
        }

        $expString = '';
        if ('' === $matcher) {
            $expString = $this->model['m'][$mType]->value;
        } else {
            $expString = Util::removeComments(Util::escapeAssertion($matcher));
        }

        $rTokens = array_values($this->model['r'][$rType]->tokens);
        $pTokens = array_values($this->model['p'][$pType]->tokens);

        if (\count($rTokens) != \count($rvals)) {
            throw new CasbinException(\sprintf('invalid request size: expected %d, got %d', \count($rTokens), \count($rvals)));
        }
        $rParameters = array_combine($rTokens, $rvals);

        if (false == $rParameters) {
            throw new CasbinException('invalid request size');
        }

        $expressionLanguage = $this->getExpressionLanguage($functions);
        $expression = "";

        $hasEval = Util::hasEval($expString);

        if (!$hasEval) {
            $expression = $expressionLanguage->parse($expString, array_merge($rTokens, $pTokens));
        }

        $policyEffects = [];
        $matcherResults = [];

        $effect = 0;
        $explainIndex = 0;

        $policyLen = \count($this->model['p'][$pType]->policy);
        if (0 != $policyLen && (strpos($expString, $pType . '_') !== false)) {
            foreach ($this->model['p'][$pType]->policy as $policyIndex => $pvals) {
                $parameters = array_combine($pTokens, $pvals);
                if (false == $parameters) {
                    throw new CasbinException('invalid policy size');
                }

                if ($hasEval) {
                    $ruleNames = Util::getEvalValue($expString);
                    $replacements = [];
                    $pTokens_flipped = array_flip($pTokens);
                    foreach ($ruleNames as $ruleName) {
                        if (isset($pTokens_flipped[$ruleName])) {
                            $rule = Util::escapeAssertion($pvals[$pTokens_flipped[$ruleName]]);
                            $replacements[$ruleName] = $rule;
                        } else {
                            throw new CasbinException('please make sure rule exists in policy when using eval() in matcher');
                        }
                    }

                    $expWithRule = Util::replaceEvalWithMap($expString, $replacements);
                    $expression = $expressionLanguage->parse($expWithRule, array_merge($rTokens, $pTokens));
                }

                $parameters = array_merge($rParameters, $parameters);
                $result = $expressionLanguage->evaluate($expression, $parameters);

                // set to no-match at first
                $matcherResults[$policyIndex] = 0;
                if (\is_bool($result)) {
                    if ($result) {
                        $matcherResults[$policyIndex] = 1;
                    }
                } elseif (\is_float($result)) {
                    if ($result != 0) {
                        $matcherResults[$policyIndex] = 1;
                    }
                } else {
                    throw new CasbinException('matcher result should be bool, int or float');
                }
                if (isset($parameters[$pType . '_eft'])) {
                    $eft = $parameters[$pType . '_eft'];
                    if ('allow' == $eft) {
                        $policyEffects[$policyIndex] = Effector::ALLOW;
                    } elseif ('deny' == $eft) {
                        $policyEffects[$policyIndex] = Effector::DENY;
                    } else {
                        $policyEffects[$policyIndex] = Effector::INDETERMINATE;
                    }
                } else {
                    $policyEffects[$policyIndex] = Effector::ALLOW;
                }

                list($effect, $explainIndex) = $this->eft->mergeEffects($this->model['e'][$eType]->value, $policyEffects, $matcherResults, $policyIndex, $policyLen);
                if ($effect != Effector::INDETERMINATE) {
                    break;
                }
            }
        } else {
            if ($hasEval) {
                throw new EvalFunctionException("please make sure rule exists in policy when using eval() in matcher");
            }

            $matcherResults[0] = 1;

            $parameters = $rParameters;
            foreach ($this->model['p'][$pType]->tokens as $token) {
                $parameters[$token] = '';
            }

            $result = $expressionLanguage->evaluate($expression, $parameters);

            if ($result) {
                $policyEffects[0] = Effector::ALLOW;
            } else {
                $policyEffects[0] = Effector::INDETERMINATE;
            }

            list($effect, $explainIndex) = $this->eft->mergeEffects($this->model['e'][$eType]->value, $policyEffects, $matcherResults, 0, 1);
        }

        if ($explains !== null) {
            if (($explainIndex != -1) && (count($this->model['p'][$pType]->policy) > $explainIndex)) {
                $explains = $this->model['p'][$pType]->policy[$explainIndex];
            }
        }

        $result = $effect == Effector::ALLOW;

        if (Log::getLogger()->isEnabled()) {
            $reqStr = 'Request: ';
            $reqStr .= implode(', ', array_values($rvals));

            $reqStr .= sprintf(" ---> %s\n", var_export($result, true));

            $reqStr = 'Hit Policy: ';
            if (count($explains) == count($explains, COUNT_RECURSIVE)) {
                // if $explains is not multidimensional
                $reqStr .= sprintf("%s \n", '[' . implode(', ', $explains) . ']');
            } else {
                // if $explains is multidimensional
                foreach ($explains as $i => $pval) {
                    $reqStr .= sprintf("%s \n", '[' . implode(', ', $pval) . ']');
                }
            }
            Log::logPrint($reqStr);
        }

        return $result;
    }

    /**
     * @param array $functions
     *
     * @return ExpressionLanguage
     */
    protected function getExpressionLanguage(array $functions): ExpressionLanguage
    {
        $expressionLanguage = new ExpressionLanguage();
        foreach ($functions as $key => $func) {
            $expressionLanguage->register($key, function (...$args) use ($key) {
                return sprintf($key . '(%1$s)', implode(',', $args));
            }, function ($arguments, ...$args) use ($func) {
                return $func(...$args);
            });
        }

        return $expressionLanguage;
    }

    /**
     * @param string $expString
     *
     * @return string
     */
    protected function getExpString(string $expString): string
    {
        return preg_replace_callback(
            '/([\s\S]*in\s+)\(([\s\S]+)\)([\s\S]*)/',
            function ($m) {
                return $m[1] . '[' . $m[2] . ']' . $m[3];
            },
            $expString
        );
    }

    /**
     * Decides whether a "subject" can access a "object" with the operation "action", input parameters are usually: (sub, obj, act).
     *
     * @param mixed ...$rvals
     *
     * @return bool
     *
     * @throws CasbinException
     */
    public function enforce(...$rvals): bool
    {
        $explains = [];
        return $this->enforcing('', $explains, ...$rvals);
    }

    /**
     * Use a custom matcher to decides whether a "subject" can access a "object" with the operation "action",
     * input parameters are usually: (matcher, sub, obj, act), use model matcher by default when matcher is "".
     *
     * @param string $matcher
     * @param mixed ...$rvals
     *
     * @return bool
     *
     * @throws CasbinException
     */
    public function enforceWithMatcher(string $matcher, ...$rvals): bool
    {
        $explains = [];
        return $this->enforcing($matcher, $explains, ...$rvals);
    }

    /**
     * EnforceEx explain enforcement by informing matched rules
     *
     * @param mixed ...$rvals
     * @return array
     */
    public function enforceEx(...$rvals)
    {
        $explain = [];
        $result = $this->enforcing("", $explain, ...$rvals);
        return [$result, $explain];
    }

    /**
     * BuildIncrementalRoleLinks provides incremental build the role inheritance relations.
     *
     * @param integer $op policy operations.
     * @param string $ptype policy type.
     * @param string[][] $rules the rules.
     * @return void
     */
    public function buildIncrementalRoleLinks(int $op, string $ptype, array $rules): void
    {
        $this->model->buildIncrementalRoleLinks($this->rmMap, $op, "g", $ptype, $rules);
    }

    /**
     * BatchEnforce enforce in batches
     *
     * @param string[][] $requests
     * @return bool[]
     */
    public function batchEnforce(array $requests): array
    {
        return array_map(function (array $request) {
            return  $this->enforce(...$request);
        }, $requests);
    }

    /**
     * BatchEnforceWithMatcher enforce with matcher in batches
     *
     * @param string $matcher
     * @param string[][] $requests
     * @return bool[]
     */
    public function batchEnforceWithMatcher(string $matcher, array $requests): array
    {
        return array_map(function (array $request) use ($matcher) {
            return  $this->enforceWithMatcher($matcher, ...$request);
        }, $requests);
    }

    /**
     * AddNamedMatchingFunc add MatchingFunc by ptype RoleManager
     *
     * @param string $ptype
     * @param string $name
     * @param \Closure $fn
     * @return boolean
     */
    public function addNamedMatchingFunc(string $ptype, string $name, \Closure $fn): bool
    {
        if (isset($this->rmMap[$ptype])) {
            $rm = $this->rmMap[$ptype];
            $rm->addMatchingFunc($name, $fn);
            return true;
        }
        return false;
    }

    /**
     * AddNamedDomainMatchingFunc add MatchingFunc by ptype to RoleManager
     *
     * @param string $ptype
     * @param string $name
     * @param \Closure $fn
     * @return boolean
     */
    public function addNamedDomainMatchingFunc(string $ptype, string $name, \Closure $fn): bool
    {
        if (isset($this->rmMap[$ptype])) {
            $rm = $this->rmMap[$ptype];
            $rm->addDomainMatchingFunc($name, $fn);
            return true;
        }
        return false;
    }
}
