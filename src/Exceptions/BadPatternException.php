<?php

declare(strict_types=1);

namespace Casbin\Exceptions;

/**
 * BadPatternException.
 *
 * Thrown internally by the glob matcher for malformed patterns; it never
 * escapes the matcher - globMatch collapses it into a non-match.
 */
class BadPatternException extends CasbinException
{

}
