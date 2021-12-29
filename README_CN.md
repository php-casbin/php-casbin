PHP-Casbin
====

[![Scrutinizer Code Quality](https://scrutinizer-ci.com/g/php-casbin/php-casbin/badges/quality-score.png?b=master)](https://scrutinizer-ci.com/g/php-casbin/php-casbin/?branch=master)
[![Default](https://github.com/php-casbin/php-casbin/workflows/build/badge.svg?branch=master)](https://github.com/php-casbin/php-casbin/actions)
[![Coverage Status](https://coveralls.io/repos/github/php-casbin/php-casbin/badge.svg)](https://coveralls.io/github/php-casbin/php-casbin)
[![Latest Stable Version](https://poser.pugx.org/casbin/casbin/v/stable)](https://packagist.org/packages/casbin/casbin)
[![Total Downloads](https://poser.pugx.org/casbin/casbin/downloads)](https://packagist.org/packages/casbin/casbin)
[![License](https://poser.pugx.org/casbin/casbin/license)](https://packagist.org/packages/casbin/casbin)
[![Gitter](https://badges.gitter.im/Join%20Chat.svg)](https://gitter.im/casbin/lobby)

**好消息**: [Laravel-authz](https://github.com/php-casbin/laravel-authz) 现已发布，一个专为Laravel打造的授权库.

**PHP-Casbin** 是一个强大的、高效的开源访问控制框架，它支持基于各种[访问控制模型](https://en.wikipedia.org/wiki/Computer_security_model)的权限管理。

## Casbin支持的编程语言:

[![golang](https://casbin.org/img/langs/golang.png)](https://github.com/casbin/casbin) | [![java](https://casbin.org/img/langs/java.png)](https://github.com/casbin/jcasbin) | [![nodejs](https://casbin.org/img/langs/nodejs.png)](https://github.com/casbin/node-casbin) | [![php](https://casbin.org/img/langs/php.png)](https://github.com/php-casbin/php-casbin)
----|----|----|----
[Casbin](https://github.com/casbin/casbin) | [jCasbin](https://github.com/casbin/jcasbin) | [node-Casbin](https://github.com/casbin/node-casbin) | [PHP-Casbin](https://github.com/php-casbin/php-casbin)
production-ready | production-ready | production-ready | production-ready

[![python](https://casbin.org/img/langs/python.png)](https://github.com/casbin/pycasbin) | [![dotnet](https://casbin.org/img/langs/dotnet.png)](https://github.com/casbin/Casbin.NET) | [![c++](https://casbin.org/img/langs/cpp.png)](https://github.com/casbin/casbin-cpp) | [![rust](https://casbin.org/img/langs/rust.png)](https://github.com/casbin/casbin-rs)
----|----|----|----
[PyCasbin](https://github.com/casbin/pycasbin) | [Casbin.NET](https://github.com/casbin/Casbin.NET) | [Casbin-CPP](https://github.com/casbin/casbin-cpp) | [Casbin-RS](https://github.com/casbin/casbin-rs)
production-ready | production-ready | beta-test | production-ready

## 安装

通过`Composer`安装:

```
composer require casbin/casbin
```

## 快速开始

1. 通过`model`和`policy`文件初始化一个`Enforcer`实例:

```php
require_once './vendor/autoload.php';

use Casbin\Enforcer;

$e = new Enforcer("path/to/model.conf", "path/to/policy.csv");
```

2. 在需要进行访问控制的位置，通过以下代码进行权限验证:

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

## 目录

- [支持的Models](#支持的Models)
- [工作原理](#工作原理)
- [特性](#特性)
- [文档](#文档)
- [在线编辑器](#在线编辑器)
- [教程](#教程)
- [Policy管理](#Policy管理)
- [Policy持久化](#Policy持久化)
- [Role管理](#Role管理)
- [例子](#例子)
- [我们的采用者](#我们的采用者)
- [协议](#协议)
- [联系](#联系)

## 支持的Models

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

## 工作原理

在 Casbin 中, 访问控制模型被抽象为基于 **PERM (Policy, Effect, Request, Matcher)** 的一个文件。 因此，切换或升级项目的授权机制与修改配置一样简单。 您可以通过组合可用的模型来定制您自己的访问控制模型。 例如，您可以在一个model中获得RBAC角色和ABAC属性，并共享一组policy规则。

Casbin中最基本、最简单的`model`是ACL。ACL中的`Model` CONF为：

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

ACL `Model`的示例`Policy`如下:

```
p, alice, data1, read
p, bob, data2, write
```

这表示:

- alice对data1有读权限
- bob对data2有写权限

## 特性

Casbin 做了什么:

1. 自定义请求的格式，默认的请求格式为``{subject, object, action}``。
2. 访问控制模型及其策略的存储。
3. 支持RBAC中的多层角色继承，不止主体可以有角色，资源也可以具有角色。
4. 支持超级用户，如 ``root`` 或 ``Administrator``，超级用户可以不受授权策略的约束访问任意资源。
5. 支持多种内置的操作符，如 ``keyMatch``，方便对路径式的资源进行管理，如 ``/foo/bar`` 可以映射到 ``/foo*``。

Casbin 不做的事情:

1. 身份认证 `authentication`（即验证用户的用户名、密码），`casbin`只负责访问控制。应该有其他专门的组件负责身份认证，然后由`casbin`进行访问控制，二者是相互配合的关系。
2. 管理用户列表或角色列表。 `Casbin` 认为由项目自身来管理用户、角色列表更为合适， 用户通常有他们的密码，但是 `Casbin`的设计思想并不是把它作为一个存储密码的容器。 而是存储RBAC方案中用户和角色之间的映射关系。 

## 文档

https://casbin.org/docs/zh-CN/overview

## 在线编辑器

你也可以使用在线编辑器(https://casbin.org/editor/) 在你的浏览器里编写Casbin模型和策略。 它提供了一些比如 `语法高亮`以及`代码补全`这样的功能，就像编程语言的IDE一样。

## 教程

https://casbin.org/docs/zh-CN/tutorials

## Policy管理

Casbin 提供两组 API 来管理权限:

- [管理API](https://github.com/php-casbin/php-casbin/blob/master/src/ManagementApi.php): Casbin的底层原生API，支持全部的策略管理功能。点击 [这里](https://github.com/php-casbin/php-casbin/blob/master/tests/Unit/ManagementApiTest.php) 查看更多例子。
- [RBAC API](https://github.com/php-casbin/php-casbin/blob/master/src/RbacApi.php): 对于RBAC, 是一个更加友好的 API。 此 API 是管理 API 中的一个子集。 RBAC 用户可以使用此 API 来简化代码。 点击 [这里](https://github.com/php-casbin/php-casbin/blob/master/tests/Unit/RbacApiTest.php) 查看更多例子。

同时也提供了一个简单的前端页面来管理`Model`和`Policy`：

![model editor](https://hsluoyz.github.io/casbin/ui_model_editor.png)

![policy editor](https://hsluoyz.github.io/casbin/ui_policy_editor.png)

## Policy持久化

在`Casbin`中，适配器(`adapter`，`Casbin`的中间件)实现了`policy`规则写入持久层的细节。 `Casbin`的用户可以调用`adapter`的`loadPolicy()`方法从持久层中加载`policy`规则， 同样也可以调用`savePolicy()`方法将`Policy`规则保存到持久层中。 为了保持代码轻量, 我们没有将`adapter`的代码放在主库中。

以下是`PHP-Casbin`支持的适配器：（欢迎更多新的第三方贡献的适配器，可以联系我们添加在下面)

Adapter | Type | Author | Description
----|------|----|----
[File Adapter (内置)](https://casbin.org/docs/zh-CN/policy-storage#file-adapter-built-in) | File | php-casbin | 存储到[.CSV (Comma-Separated Values)](https://en.wikipedia.org/wiki/Comma-separated_values) 文件中
[Database Adapter](https://github.com/php-casbin/database-adapter) | Database | php-casbin | 支持存储到MySQL, PostgreSQL, SQLite, Microsoft SQL Server数据库的适配器

更多适配器的内容，请参考文档: https://casbin.org/docs/zh-CN/policy-storage

## Role管理

角色管理器用于在`Casbin`中管理`RBAC`多层角色继承(用户-角色的关系)。角色管理器可以从Casbin的`Policy`规则或者外部数据源（如LDAP, Okta, Auth0, Azure AD等）获取角色数据。我们支持多种角色管理器，为了保持代码轻量，我们没有将除了内置的默认的角色管理器以外的角色管理器放在主库中。以下是支持的角色管理器：（欢迎更多新的第三方贡献的角色管理器，可以联系我们添加在下面)

Role manager | Author | Description
----|----|----
[Default Role Manager (内置)](https://github.com/php-casbin/php-casbin/blob/master/src/Rbac/DefaultRoleManager/RoleManager.php) | php-casbin | 支持多层角色继承

提示: 所有的角色管理器必须实现[RoleManager](https://github.com/php-casbin/php-casbin/blob/master/src/Rbac/RoleManager.php) 接口。 可以参考[Default Role Manager](https://github.com/php-casbin/php-casbin/blob/master/src/Rbac/DefaultRoleManager/RoleManager.php) 。

## 例子

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

## 我们的采用者

### Web框架

- [Laravel](https://laravel.com/): 为WEB艺术家创造的PHP框架, 通过这个扩展: [laravel-casbin](https://github.com/php-casbin/laravel-casbin)

- [Yii PHP Framework](https://www.yiiframework.com/): 一个高性能的，适用于开发WEB2.0应用的PHP框架, 通过这个扩展: [yii-casbin](https://github.com/php-casbin/yii-casbin)

- [CakePHP](https://cakephp.org/): 快速、稳定的PHP框架, 通过这个扩展: [cake-casbin](https://github.com/php-casbin/cake-casbin)

- [ThinkPHP](http://www.thinkphp.cn/): 一个免费开源的，快速、简单的面向对象的轻量级PHP开发框架, 通过这个扩展: [think-casbin](https://github.com/php-casbin/think-casbin)

## 协议

`PHP-Casbin` 采用 [Apache 2.0 license](LICENSE) 开源协议发布。

## 联系

有问题或者功能建议，请联系我们或者提交PR:
- https://github.com/php-casbin/php-casbin/issues
- techlee@qq.com
- QQ群: [546057381](//shang.qq.com/wpa/qunwpa?idkey=8ac8b91fc97ace3d383d0035f7aa06f7d670fd8e8d4837347354a31c18fac885)
