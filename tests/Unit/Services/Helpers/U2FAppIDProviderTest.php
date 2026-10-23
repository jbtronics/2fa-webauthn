<?php

declare(strict_types=1);

namespace Jbtronics\TFAWebauthn\Tests\Unit\Services\Helpers;

use Jbtronics\TFAWebauthn\Services\Helpers\U2FAppIDProvider;
use Jbtronics\TFAWebauthn\Tests\Fixtures\Factory;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Symfony\Component\HttpFoundation\RequestStack;

final class U2FAppIDProviderTest extends TestCase
{
    /**
     * @return iterable<string, array{string, string}>
     */
    public static function provideRequests(): iterable
    {
        yield 'https default port' => ['https://example.com/2fa', 'https://example.com'];
        yield 'http default port' => ['http://example.com/2fa', 'http://example.com'];
        yield 'custom port' => ['https://example.com:8443/2fa', 'https://example.com:8443'];
    }

    #[DataProvider('provideRequests')]
    public function testAppIDFromCurrentRequest(string $uri, string $expected): void
    {
        $provider = new U2FAppIDProvider(Factory::requestStack($uri));

        self::assertSame($expected, $provider->getAppID());
    }

    public function testOverrideWins(): void
    {
        $provider = new U2FAppIDProvider(Factory::requestStack('https://example.com/2fa'), 'https://legacy.example.com');

        self::assertSame('https://legacy.example.com', $provider->getAppID());
    }

    public function testEmptyOverrideFallsBackToRequest(): void
    {
        $provider = new U2FAppIDProvider(Factory::requestStack('https://example.com/2fa'), '');

        self::assertSame('https://example.com', $provider->getAppID());
    }

    public function testNoRequestThrows(): void
    {
        $provider = new U2FAppIDProvider(new RequestStack());

        $this->expectException(\RuntimeException::class);
        $provider->getAppID();
    }
}
