<?php

declare(strict_types=1);

namespace Casbin;

use Casbin\Effector\{DefaultEffector, Effector};
use Casbin\Exceptions\{CasbinException, EvalFunctionException, InvalidFilePathException};
use Casbin\Log\Logger;
use Casbin\Log\Logger\DefaultLogger;
use Casbin\Model\FunctionMap;
use Casbin\Model\Model;
use Casbin\Persist\Adapter;
use Casbin\Persist\Adapters\FileAdapter;
use Casbin\Persist\FilteredAdapter;
use Casbin\Persist\{Watcher, WatcherEx};
use Casbin\Rbac\DefaultRoleManager\ConditionalDomainManager as DefaultConditionalDomainManager;
use Casbin\Rbac\DefaultRoleManager\ConditionalRoleManager as DefaultConditionalRoleManager;
use Casbin\Rbac\DefaultRoleManager\RoleManager as DefaultRoleManager;
use Casbin\Rbac\DefaultRoleManager\DomainManager as DefaultDomainManager;
use Casbin\Rbac\{ConditionalRoleManager, RoleManager};
use Casbin\Util\{BuiltinOperations, Util};
use Closure;
use Symfony\Component\ExpressionLanguage\ExpressionLanguage;
use function sprintf;

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
    protected string $modelPath;

    /**
     * Model.
     *
     * @var Model
     */
    protected Model $model;

    /**
     * FunctionMap.
     *
     * @var FunctionMap
     */
    protected FunctionMap $fm;

    /**
     * Effector.
     *
     * @var Effector
     */
    protected Effector $eft;

    /**
     * Adapter.
     *
     * @var Adapter|null
     */
    protected ?Adapter $adapter;

    /**
     * Watcher.
     *
     * @var Watcher|null
     */
    protected ?Watcher $watcher;

    /**
     * RmMap.
     *
     * @var array<string, RoleManager>
     */
    protected array $rmMap;

    /**
     * CondRmMap.
     *
     * @var array<string, ConditionalRoleManager>
     */
    protected array $condRmMap;

    /**
     * $enabled.
     *
     * @var bool
     */
    protected bool $enabled;

    /**
     * $autoSave.
     *
     * @var bool
     */
    protected bool $autoSave;

    /**
     * $autoBuildRoleLinks.
     *
     * @var bool
     */
    protected bool $autoBuildRoleLinks;

    /**
     * $autoNotifyWatcher.
     *
     * @var bool
     */
    protected bool $autoNotifyWatcher;

    /**
     * $logger.
     *
     * @var Logger
     */
    protected Logger $logger;

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
     * @param string|Model|null $model
     * @param string|Adapter|null $adapter
     * @param Logger|null $logger
     * @param bool|null $enableLog
     *
     * @throws CasbinException
     */
    public function __construct(string|Model|null $model = null, string|Adapter|null $adapter = null, ?Logger $logger = null, ?bool $enableLog = null)
    {
        $this->logger = $logger ?? new DefaultLogger();

        if (!is_null($enableLog)) {
            $this->enableLog($enableLog);
        }

        if (is_null($model) && is_null($adapter)) {
            return;
        }

        if (is_string($model)) {
            if (is_string($adapter) || is_null($adapter)) {
                $this->initWithFile($model, $adapter ?? '');
            } else if ($adapter instanceof Adapter) {
                $this->initWithAdapter($model, $adapter);
            }
        } else if ($model instanceof Model) {
            if ($adapter instanceof Adapter || is_null($adapter)) {
                $this->initWithModelAndAdapter($model, $adapter);
            } else {
                throw new CasbinException('Invalid parameters for enforcer.');
            }
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
    public function initWithModelAndAdapter(Model $m, ?Adapter $adapter): void
    {
        $this->adapter = $adapter;
        $this->model = $m;
        $this->model->setLogger($this->logger);
        $this->model->printModel();

        $this->fm = Model::loadFunctionMap();

        $this->initialize();

        // Do not initialize the full policy when using a filtered adapter
        $ok = $this->adapter instanceof FilteredAdapter ? $this->adapter->isFiltered() : false;

        if (!is_null($this->adapter) && !$ok) {
            $this->loadPolicy();
        }
    }

    /**
     * Sets the current logger.
     *
     * @param Logger $logger
     */
    public function setLogger(Logger $logger): void
    {
        $this->logger = $logger;
        $this->model->setLogger($this->logger);
        foreach ($this->rmMap as $rm) {
            $rm->setLogger($this->logger);
        }
        foreach ($this->condRmMap as $rm) {
            $rm->setLogger($this->logger);
        }
    }

    /**
     * Initializes an enforcer with a database adapter.
     */
    protected function initialize(): void
    {
        $this->rmMap = [];
        $this->condRmMap = [];
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
        $this->watcher->setUpdateCallback(fn() => $this->loadPolicy());
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
        $newModel = $this->loadPolicyFromAdapter($this->model);
        if (!is_null($newModel)) {
            $this->applyModifiedModel($newModel);
        }
    }

    /**
     * Loads policy from the current adapter.
     *
     * @param Model $baseModel
     *
     * @return Model|null
     */
    public function loadPolicyFromAdapter(Model $baseModel): ?Model
    {
        $newModel = clone $baseModel;
        $newModel->clearPolicy();

        try {
            $this->adapter?->loadPolicy($newModel);
            $newModel->sortPoliciesBySubjectHierarchy();
            $newModel->sortPoliciesByPriority();
        } catch (InvalidFilePathException) {
            return null;
        } catch (\Throwable $e) {
            throw $e;
        }

        return $newModel;
    }

    /**
     * Applies a modified model to the current enforcer.
     *
     * @param Model $newModel
     */
    public function applyModifiedModel(Model $newModel): void
    {
        $ok = false;
        $needToRebuild = false;

        try {
            if ($this->autoBuildRoleLinks) {
                $needToRebuild = true;

                $this->rebuildRoleLinks($newModel);
                $this->rebuildConditionalRoleLinks($newModel);
            }
            $this->model = $newModel;
            $ok = true;
        } finally {
            if (!$ok) {
                if ($this->autoBuildRoleLinks && $needToRebuild) {
                    $this->buildRoleLinks();
                }
            }
        }
    }

    /**
     * Rebuilds the role inheritance relations based on the new model.
     *
     * @param Model $newModel
     */
    public function rebuildRoleLinks(Model $newModel): void
    {
        if (count($this->rmMap) !== 0) {
            foreach ($this->rmMap as $rm) {
                $rm->clear();
            }

            $newModel->buildRoleLinks($this->rmMap);
        }
    }

    /**
     * Rebuilds the conditional role inheritance relations based on the new model.
     *
     * @param Model $newModel
     */
    public function rebuildConditionalRoleLinks(Model $newModel): void
    {
        if (!empty($this->condRmMap)) {
            foreach ($this->condRmMap as $rm) {
                $rm->clear();
            }

            $newModel->buildConditionalRoleLinks($this->condRmMap);
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

        $this->model->sortPoliciesBySubjectHierarchy();
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

        $this->adapter?->savePolicy($this->model);

        if ($this->autoNotifyWatcher) {
            if ($this->watcher instanceof WatcherEx) {
                $this->watcher->updateForSavePolicy($this->model);
            } else {
                $this->watcher?->update();
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
                    continue;
                }

                $tokensCount = count($value->tokens);
                $paramsTokensCount = count($value->paramsTokens);
                if ($tokensCount <= 2) {
                    if ($paramsTokensCount === 0) {
                        $value->rm = new DefaultRoleManager(10);
                        $this->rmMap[$ptype] = $value->rm;
                    } else {
                        $value->condRm = new DefaultConditionalRoleManager(10);
                        $this->condRmMap[$ptype] = $value->condRm;
                    }
                }
                if ($tokensCount > 2) {
                    if ($paramsTokensCount === 0) {
                        $value->rm = new DefaultDomainManager(10);
                        $this->rmMap[$ptype] = $value->rm;
                    } else {
                        $value->condRm = new DefaultConditionalDomainManager(10);
                        $this->condRmMap[$ptype] = $value->condRm;
                    }
                    $matchFunc = 'keyMatch(r_dom, p_dom)';
                    if (isset($this->model['m']['m']) && str_contains($this->model['m']['m']->value, $matchFunc)) {
                        $this->addNamedDomainMatchingFunc('g', 'keyMatch', fn(string $key1, string $key2) => BuiltinOperations::keyMatch($key1, $key2));
                    }
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
        $this->logger->enableLog($enabled);
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
                if (!is_null($ast->rm)) {
                    $functions[$key] = BuiltinOperations::generateGFunction($ast->rm);
                }
                if (!is_null($ast->condRm)) {
                    $functions[$key] = BuiltinOperations::generateConditionalGFunction($ast->condRm);
                }
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

        $expString = '' === $matcher ? $this->model['m'][$mType]->value : Util::removeComments(Util::escapeAssertion($matcher));

        if (!isset($this->model['r'][$rType])){
            throw new CasbinException(sprintf('rType[%s] not defined', $rType));
        }

        if (!isset($this->model['p'][$pType])){
            throw new CasbinException(sprintf('pType[%s] not defined', $pType));
        }

        if (!isset($this->model['e'][$eType])){
            throw new CasbinException(sprintf('eType[%s] not defined', $eType));
        }

        $rTokens = array_values($this->model['r'][$rType]->tokens);
        $pTokens = array_values($this->model['p'][$pType]->tokens);

        if (count($rTokens) != count($rvals)) {
            throw new CasbinException(sprintf('invalid request size: expected %d, got %d, rvals: %s', count($rTokens), count($rvals), json_encode($rvals)));
        }
        $rParameters = array_combine($rTokens, $rvals);

        $parameters = [];
        $hasEval = Util::hasEval($expString);
        if ($hasEval) {
            $functions['eval'] = function (string $exp) use ($functions, &$parameters) {
                return $this->getExpressionLanguage($functions)->evaluate(Util::escapeAssertion($exp), $parameters);
            };
        }

        $expressionLanguage = $this->getExpressionLanguage($functions);
        $expression = $expressionLanguage->parse($expString, array_merge($rTokens, $pTokens));

        $policyEffects = [];
        $matcherResults = [];

        $effect = 0;
        $explainIndex = 0;

        $policyLen = count($this->model['p'][$pType]->policy);
        if (0 != $policyLen && str_contains($expString, $pType . '_')) {
            foreach ($this->model['p'][$pType]->policy as $policyIndex => $pvals) {
                if (count($pTokens) != count($pvals)) {
                    throw new CasbinException(sprintf("invalid policy size: expected %d, got %d, pvals: %s", count($pTokens), count($pvals), json_encode($pvals)));
                }

                $parameters = array_merge($rParameters, array_combine($pTokens, $pvals));
                $result = $expressionLanguage->evaluate($expression, $parameters);

                // set to no-match at first
                $matcherResults[$policyIndex] = 0;
                if (is_bool($result)) {
                    if ($result) {
                        $matcherResults[$policyIndex] = 1;
                    }
                } elseif (is_float($result)) {
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

                [$effect, $explainIndex] = $this->eft->mergeEffects($this->model['e'][$eType]->value, $policyEffects, $matcherResults, $policyIndex, $policyLen);
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

            [$effect, $explainIndex] = $this->eft->mergeEffects($this->model['e'][$eType]->value, $policyEffects, $matcherResults, 0, 1);
        }

        if ($explains !== null) {
            if (($explainIndex != -1) && (count($this->model['p'][$pType]->policy) > $explainIndex)) {
                $explains = $this->model['p'][$pType]->policy[$explainIndex];
            }
        }

        $result = $effect == Effector::ALLOW;

        $this->logger->logEnforce($matcher, $rvals, $result, $explains);

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
            $expressionLanguage->register(
                $key,
                static fn(...$args): string => sprintf($key . '(%1$s)', implode(',', $args)),
                static fn($arguments, ...$args) => $func(...$args)
            );
        }

        return $expressionLanguage;
    }

    /**
     * @param string $expString
     *
     * @return string|null
     */
    protected function getExpString(string $expString): string|null
    {
        return preg_replace_callback(
            '/([\s\S]*in\s+)\(([\s\S]+)\)([\s\S]*)/',
            static fn($m): string => $m[1] . '[' . $m[2] . ']' . $m[3],
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
     * BuildIncrementalConditionalRoleLinks provides incremental build the conditional role inheritance relations.
     *
     * @param integer $op policy operations.
     * @param string $ptype policy type.
     * @param string[][] $rules the rules.
     * @return void
     */
    public function buildIncrementalConditionalRoleLinks(int $op, string $ptype, array $rules): void
    {
        $this->model->buildIncrementalConditionalRoleLinks($this->condRmMap, $op, "g", $ptype, $rules);
    }

    /**
     * BatchEnforce enforce in batches
     *
     * @param string[][] $requests
     * @return bool[]
     */
    public function batchEnforce(array $requests): array
    {
        return array_map(fn(array $request) => $this->enforce(...$request), $requests);
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
        return array_map(fn(array $request) => $this->enforceWithMatcher($matcher, ...$request), $requests);
    }

    /**
     * AddNamedMatchingFunc add MatchingFunc by ptype RoleManager
     *
     * @param string $ptype
     * @param string $name
     * @param Closure $fn
     * @return boolean
     */
    public function addNamedMatchingFunc(string $ptype, string $name, Closure $fn): bool
    {
        if (isset($this->rmMap[$ptype])) {
            $rm = &$this->rmMap[$ptype];
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
     * @param Closure $fn
     * @return boolean
     */
    public function addNamedDomainMatchingFunc(string $ptype, string $name, Closure $fn): bool
    {
        if (isset($this->rmMap[$ptype])) {
            $rm = &$this->rmMap[$ptype];
            $rm->addDomainMatchingFunc($name, $fn);
            return true;
        }
        return false;
    }

    /**
     * AddNamedLinkConditionFunc Add condition function fn for Link userName->roleName,
     * when fn returns true, Link is valid, otherwise invalid.
     *
     * @param string $ptype
     * @param string $user
     * @param string $role
     * @param Closure $fn
     * @return boolean
     */
    public function addNamedLinkConditionFunc(string $ptype, string $user, string $role, Closure $fn): bool
    {
        if (isset($this->condRmMap[$ptype])) {
            $rm = &$this->condRmMap[$ptype];
            $rm->addLinkConditionFunc($user, $role, $fn);
            return true;
        }
        return false;
    }

    /**
     * AddNamedDomainLinkConditionFunc Add condition function fn for Link userName-> {roleName, domain},
     * when fn returns true, Link is valid, otherwise invalid.
     *
     * @param string $ptype
     * @param string $user
     * @param string $role
     * @param string $domain
     * @param Closure $fn
     *
     * @return boolean
     */
    public function addNamedDomainLinkConditionFunc(string $ptype, string $user, string $role, string $domain, Closure $fn): bool
    {
        if (isset($this->condRmMap[$ptype])) {
            $rm = &$this->condRmMap[$ptype];
            $rm->addDomainLinkConditionFunc($user, $role, $domain, $fn);
            return true;
        }
        return false;
    }

    /**
     * SetNamedLinkConditionFuncParams Sets the parameters of the condition function fn for Link userName->roleName.
     *
     * @param string $ptype
     * @param string $user
     * @param string $role
     * @param string ...$params
     *
     * @return boolean
     */
    public function setNamedLinkConditionFuncParams(string $ptype, string $user, string $role, string ...$params): bool
    {
        if (isset($this->condRmMap[$ptype])) {
            $rm = &$this->condRmMap[$ptype];
            $rm->setLinkConditionFuncParams($user, $role, ...$params);
            return true;
        }
        return false;
    }

    /**
     * SetNamedDomainLinkConditionFuncParams Sets the parameters of the condition function fn
     * for Link userName->{roleName, domain}.
     *
     * @param string $ptype
     * @param string $user
     * @param string $role
     * @param string $domain
     * @param string ...$params
     *
     * @return boolean
     */
    public function setNamedDomainLinkConditionFuncParams(string $ptype, string $user, string $role, string $domain, string ...$params): bool
    {
        if (isset($this->condRmMap[$ptype])) {
            $rm = &$this->condRmMap[$ptype];
            $rm->setDomainLinkConditionFuncParams($user, $role, $domain, ...$params);
            return true;
        }
        return false;
    }
}
