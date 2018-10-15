<?php
require_once './vendor/autoload.php';

use Casbin\Enforcer;
use Casbin\Util\Log;

Log::$enableLog = true;

$e = new Enforcer(__DIR__ . '/examples/modelandpolicy/basic_model.conf', __DIR__ . "/examples/modelandpolicy/basic_policy.csv");

$sub = "alice"; // 想要访问资源的用户。$cfg
$obj = "data1"; // 将被访问的资源。buildRoleLinks
$act = "read"; // 用户对资源执行的操作。

if ($e->enforce($sub, $obj, $act) === true) {
    // 允许 alice 读取 data1
    echo "允许 alice 读取 data1";
} else {
    // 拒绝请求, 显示错误
    echo "拒绝请求, 显示错误";
}
