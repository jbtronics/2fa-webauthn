<?php

declare(strict_types=1);

namespace Jbtronics\TFAWebauthn;

use Symfony\Component\HttpKernel\Bundle\Bundle;

class TFAWebauthnBundle extends Bundle
{
    /**
     * The bundle class lives in src/, but templates/ and config/ are at the package root.
     * Returning the root makes TwigBundle register templates/ as the @TFAWebauthn namespace.
     */
    public function getPath(): string
    {
        return \dirname(__DIR__);
    }
}
