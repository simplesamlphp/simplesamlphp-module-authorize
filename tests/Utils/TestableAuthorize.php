<?php

/**
 * Subclass authorize filter to make it unit testable.
 */

declare(strict_types=1);

namespace SimpleSAML\Module\Authorize\Tests\Utils;

use SimpleSAML\Module\authorize\Auth\Process\Authorize;

class TestableAuthorize extends Authorize
{
    /**
     * Override the redirect behavior since its difficult to test
     * @param array $state the state
     */
    protected function unauthorized(array &$state): void
    {
        $state['NOT_AUTHORIZED'] = true;
    }
}
