<?php

declare(strict_types=1);

namespace Casbin\Constant;

/**
 * Class Constant
 * Contains constants used in Casbin.
 *
 * @author 1692898084@qq.com
 */
final class Constants
{
    const ACTION_INDEX = 'act';
    const DOMAIN_INDEX = 'dom';
    const SUBJECT_INDEX = 'sub';
    const OBJECT_INDEX = 'obj';
    const PRIORITY_INDEX = 'priority';

    const ALLOW_OVERRIDE_EFFECT = 'some(where (p_eft == allow))';
    const DENY_OVERRIDE_EFFECT = '!some(where (p_eft == deny))';
    const ALLOW_AND_DENY_EFFECT = 'some(where (p_eft == allow)) && !some(where (p_eft == deny))';
    const PRIORITY_EFFECT = 'priority(p_eft) || deny';
    const SUBJECT_PRIORITY_EFFECT = 'subjectPriority(p_eft) || deny';
}
