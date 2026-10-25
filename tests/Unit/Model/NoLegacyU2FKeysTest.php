<?php

declare(strict_types=1);

namespace Jbtronics\TFAWebauthn\Tests\Unit\Model;

use Jbtronics\TFAWebauthn\Model\NoLegacyU2FKeys;
use PHPUnit\Framework\TestCase;

final class NoLegacyU2FKeysTest extends TestCase
{
    public function testReturnsNoKeys(): void
    {
        $user = new class {
            use NoLegacyU2FKeys;
        };

        self::assertSame([], $user->getLegacyU2FKeys());
    }
}
