PHP-Casbin
====

[![StyleCI](https://github.styleci.io/repos/153135401/shield?branch=master)](https://github.styleci.io/repos/153135401)
[![Build Status](https://travis-ci.org/php-casbin/php-casbin.svg?branch=master)](https://travis-ci.org/php-casbin/php-casbin)
[![Coverage Status](https://coveralls.io/repos/github/php-casbin/php-casbin/badge.svg)](https://coveralls.io/github/php-casbin/php-casbin)
[![Latest Stable Version](https://poser.pugx.org/casbin/casbin/v/stable)](https://packagist.org/packages/casbin/casbin)
[![Total Downloads](https://poser.pugx.org/casbin/casbin/downloads)](https://packagist.org/packages/casbin/casbin)
[![License](https://poser.pugx.org/casbin/casbin/license)](https://packagist.org/packages/casbin/casbin)
[![Gitter](https://badges.gitter.im/Join%20Chat.svg)](https://gitter.im/casbin/lobby)

[中文文档](https://github.com/php-casbin/php-casbin/blob/master/README_CN.md)

**PHP-Casbin** is a powerful and efficient open-source access control library for PHP projects. It provides support for enforcing authorization based on various [access control models](https://en.wikipedia.org/wiki/Computer_security_model).

## All the languages supported by Casbin:

[![golang](https://casbin.org/docs/assets/langs/golang.png)](https://github.com/casbin/casbin) | [![java](https://casbin.org/docs/assets/langs/java.png)](https://github.com/casbin/jcasbin) | [![nodejs](https://casbin.org/docs/assets/langs/nodejs.png)](https://github.com/casbin/node-casbin) | [![php](https://casbin.org/docs/assets/langs/php.png)](https://github.com/php-casbin/php-casbin)
----|----|----|----
[Casbin](https://github.com/casbin/casbin) | [jCasbin](https://github.com/casbin/jcasbin) | [node-Casbin](https://github.com/casbin/node-casbin) | [PHP-Casbin](https://github.com/php-casbin/php-casbin)
production-ready | production-ready | production-ready | production-ready

## Installation

Require this package in the `composer.json` of your project. This will download the package:

```
composer require casbin/casbin
```

## Get started

1. New a Casbin enforcer with a model file and a policy file:

```php
require_once './vendor/autoload.php';

use Casbin\Enforcer;

$e = new Enforcer("path/to/model.conf", "path/to/policy.csv");
```

2. Add an enforcement hook into your code right before the access happens:

```php
$sub = "alice"; // the user that wants to access a resource.
$obj = "data1"; // the resource that is going to be accessed.
$act = "read"; // the operation that the user performs on the resource.

if ($e->enforce($sub, $obj, $act) === true) {
    // permit alice to read data1
} else {
    // deny the request, show an error
}
```

## Table of contents

- [Supported models](#supported-models)
- [How it works?](#how-it-works)
- [Features](#features)
- [Documentation](#documentation)
- [Online editor](#online-editor)
- [Tutorials](#tutorials)
- [Policy management](#policy-management)
- [Policy persistence](#policy-persistence)
- [Role manager](#role-manager)
- [Examples](#examples)
- [Our adopters](#our-adopters)

## Supported models

1. [**ACL (Access Control List)**](https://en.wikipedia.org/wiki/Access_control_list)
2. **ACL with [superuser](https://en.wikipedia.org/wiki/Superuser)**
3. **ACL without users**: especially useful for systems that don't have authentication or user log-ins.
3. **ACL without resources**: some scenarios may target for a type of resources instead of an individual resource by using permissions like ``write-article``, ``read-log``. It doesn't control the access to a specific article or log.
4. **[RBAC (Role-Based Access Control)](https://en.wikipedia.org/wiki/Role-based_access_control)**
5. **RBAC with resource roles**: both users and resources can have roles (or groups) at the same time.
6. **RBAC with domains/tenants**: users can have different role sets for different domains/tenants.
7. **[ABAC (Attribute-Based Access Control)](https://en.wikipedia.org/wiki/Attribute-Based_Access_Control)**: syntax sugar like ``resource.Owner`` can be used to get the attribute for a resource.
8. **[RESTful](https://en.wikipedia.org/wiki/Representational_state_transfer)**: supports paths like ``/res/*``, ``/res/:id`` and HTTP methods like ``GET``, ``POST``, ``PUT``, ``DELETE``.
9. **Deny-override**: both allow and deny authorizations are supported, deny overrides the allow.
10. **Priority**: the policy rules can be prioritized like firewall rules.

## How it works?

In php-casbin, an access control model is abstracted into a CONF file based on the **PERM metamodel (Policy, Effect, Request, Matchers)**. So switching or upgrading the authorization mechanism for a project is just as simple as modifying a configuration. You can customize your own access control model by combining the available models. For example, you can get RBAC roles and ABAC attributes together inside one model and share one set of policy rules.

The most basic and simplest model in php-casbin is ACL. ACL's model CONF is:

```ini
# Request definition
[request_definition]
r = sub, obj, act

# Policy definition
[policy_definition]
p = sub, obj, act

# Policy effect
[policy_effect]
e = some(where (p.eft == allow))

# Matchers
[matchers]
m = r.sub == p.sub && r.obj == p.obj && r.act == p.act
```

An example policy for ACL model is like:

```
p, alice, data1, read
p, bob, data2, write
```

It means:

- alice can read data1
- bob can write data2

## Features

What php-casbin does:

1. enforce the policy in the classic ``{subject, object, action}`` form or a customized form as you defined, both allow and deny authorizations are supported.
2. handle the storage of the access control model and its policy.
3. manage the role-user mappings and role-role mappings (aka role hierarchy in RBAC).
4. support built-in superuser like ``root`` or ``administrator``. A superuser can do anything without explict permissions.
5. multiple built-in operators to support the rule matching. For example, ``keyMatch`` can map a resource key ``/foo/bar`` to the pattern ``/foo*``.

What php-casbin does NOT do:

1. authentication (aka verify ``username`` and ``password`` when a user logs in)
2. manage the list of users or roles. I believe it's more convenient for the project itself to manage these entities. Users usually have their passwords, and php-casbin is not designed as a password container. However, php-casbin stores the user-role mapping for the RBAC scenario. 

## Documentation

https://casbin.org/docs/en/overview

## Online editor

You can also use the online editor (http://casbin.org/editor/) to write your php-casbin model and policy in your web browser. It provides functionality such as ``syntax highlighting`` and ``code completion``, just like an IDE for a programming language.

## Tutorials

https://casbin.org/docs/en/tutorials

## Policy management

php-casbin provides two sets of APIs to manage permissions:

- [Management API](https://github.com/php-casbin/php-casbin/blob/master/src/ManagementApi.php): the primitive API that provides full support for php-casbin policy management. See [here](https://github.com/php-casbin/php-casbin/blob/master/tests/Unit/ManagementApiTest.php) for examples.
- [RBAC API](https://github.com/php-casbin/php-casbin/blob/master/src/RbacApi.php): a more friendly API for RBAC. This API is a subset of Management API. The RBAC users could use this API to simplify the code. See [here](https://github.com/php-casbin/php-casbin/blob/master/tests/Unit/RbacApiTest.php) for examples.

We also provide a web-based UI for model management and policy management:

![model editor](https://hsluoyz.github.io/casbin/ui_model_editor.png)

![policy editor](https://hsluoyz.github.io/casbin/ui_policy_editor.png)

## Policy persistence

In php-casbin, the policy storage is implemented as an adapter (aka middleware for php-casbin). To keep light-weight, we don't put adapter code in the main library (except the default file adapter). A complete list of php-casbin adapters is provided as below. Any 3rd-party contribution on a new adapter is welcomed, please inform us and I will put it in this list:)

Adapter | Type | Author | Description
----|------|----|----
[File Adapter (built-in)](https://casbin.org/docs/en/policy-storage#file-adapter-built-in) | File | php-casbin | Persistence for [.CSV (Comma-Separated Values)](https://en.wikipedia.org/wiki/Comma-separated_values) files
[Database Adapter](https://github.com/php-casbin/database-adapter) | Database | php-casbin | MySQL, PostgreSQL, SQLite, Microsoft SQL Server are supported by Database Adapter

For details of adapters, please refer to the documentation: https://casbin.org/docs/en/policy-storage

## Role manager

The role manager is used to manage the RBAC role hierarchy (user-role mapping) in php-casbin. A role manager can retrieve the role data from php-casbin policy rules or external sources such as LDAP, Okta, Auth0, Azure AD, etc. We support different implementations of a role manager. To keep light-weight, we don't put role manager code in the main library (except the default role manager). A complete list of php-casbin role managers is provided as below. Any 3rd-party contribution on a new role manager is welcomed, please inform us and I will put it in this list:)

Role manager | Author | Description
----|----|----
[Default Role Manager (built-in)](https://github.com/php-casbin/php-casbin/blob/master/src/Rbac/DefaultRoleManager/RoleManager.php) | php-casbin | Supports role hierarchy stored in php-casbin policy

For developers: all role managers must implement the [RoleManager](https://github.com/php-casbin/php-casbin/blob/master/src/Rbac/RoleManager.php) interface. [Default Role Manager](https://github.com/php-casbin/php-casbin/blob/master/src/Rbac/DefaultRoleManager/RoleManager.php) can be used as a reference implementation.

## Examples

Model | Model file | Policy file
----|------|----
ACL | [basic_model.conf](https://github.com/php-casbin/php-casbin/blob/master/examples/basic_model.conf) | [basic_policy.csv](https://github.com/php-casbin/php-casbin/blob/master/examples/basic_policy.csv)
ACL with superuser | [basic_model_with_root.conf](https://github.com/php-casbin/php-casbin/blob/master/examples/basic_with_root_model.conf) | [basic_policy.csv](https://github.com/php-casbin/php-casbin/blob/master/examples/basic_policy.csv)
ACL without users | [basic_model_without_users.conf](https://github.com/php-casbin/php-casbin/blob/master/examples/basic_without_users_model.conf) | [basic_policy_without_users.csv](https://github.com/php-casbin/php-casbin/blob/master/examples/basic_without_users_policy.csv)
ACL without resources | [basic_model_without_resources.conf](https://github.com/php-casbin/php-casbin/blob/master/examples/basic_without_resources_model.conf) | [basic_policy_without_resources.csv](https://github.com/php-casbin/php-casbin/blob/master/examples/basic_without_resources_policy.csv)
RBAC | [rbac_model.conf](https://github.com/php-casbin/php-casbin/blob/master/examples/rbac_model.conf)  | [rbac_policy.csv](https://github.com/php-casbin/php-casbin/blob/master/examples/rbac_policy.csv)
RBAC with resource roles | [rbac_model_with_resource_roles.conf](https://github.com/php-casbin/php-casbin/blob/master/examples/rbac_with_resource_roles_model.conf)  | [rbac_policy_with_resource_roles.csv](https://github.com/php-casbin/php-casbin/blob/master/examples/rbac_with_resource_roles_policy.csv)
RBAC with domains/tenants | [rbac_model_with_domains.conf](https://github.com/php-casbin/php-casbin/blob/master/examples/rbac_with_domains_model.conf)  | [rbac_policy_with_domains.csv](https://github.com/php-casbin/php-casbin/blob/master/examples/rbac_with_domains_policy.csv)
ABAC | [abac_model.conf](https://github.com/php-casbin/php-casbin/blob/master/examples/abac_model.conf)  | N/A
RESTful | [keymatch_model.conf](https://github.com/php-casbin/php-casbin/blob/master/examples/keymatch_model.conf)  | [keymatch_policy.csv](https://github.com/php-casbin/php-casbin/blob/master/examples/keymatch_policy.csv)
Deny-override | [rbac_model_with_deny.conf](https://github.com/php-casbin/php-casbin/blob/master/examples/rbac_with_deny_model.conf)  | [rbac_policy_with_deny.csv](https://github.com/php-casbin/php-casbin/blob/master/examples/rbac_with_deny_policy.csv)
Priority | [priority_model.conf](https://github.com/php-casbin/php-casbin/blob/master/examples/priority_model.conf)  | [priority_policy.csv](https://github.com/php-casbin/php-casbin/blob/master/examples/priority_policy.csv)

## Our adopters

### Web frameworks

- [Laravel](https://laravel.com/): The PHP framework for web artisans, via plugin: [laravel-casbin](https://github.com/php-casbin/laravel-casbin)

- [Yii PHP Framework](https://www.yiiframework.com/): A fast, secure, and efficient PHP framework, via plugin: [yii-casbin](https://github.com/php-casbin/yii-casbin)

- [ThinkPHP](http://www.thinkphp.cn/): The ThinkPHP framework, via plugin: [think-casbin](https://github.com/php-casbin/think-casbin)

## License

This project is licensed under the [Apache 2.0 license](LICENSE).

## Contact

If you have any issues or feature requests, please contact us. PR is welcomed.
- https://github.com/php-casbin/php-casbin/issues
- techlee@qq.com
- Tencent QQ group: [546057381](//shang.qq.com/wpa/qunwpa?idkey=8ac8b91fc97ace3d383d0035f7aa06f7d670fd8e8d4837347354a31c18fac885)
