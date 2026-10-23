<?php

declare(strict_types=1);

namespace Jbtronics\TFAWebauthn\Tests\Unit\Helpers;

use Jbtronics\TFAWebauthn\Helpers\WebsafeBase64;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

final class WebsafeBase64Test extends TestCase
{
    /**
     * @return iterable<string, array{string, string}>
     */
    public static function provideValidInput(): iterable
    {
        yield 'empty' => ['', ''];
        yield 'padded' => ['YQ==', 'a'];
        yield 'unpadded' => ['YQ', 'a'];
        yield 'url safe chars' => ['-_-_', "\xfb\xff\xbf"];
        yield 'standard chars still accepted' => ['+/+/', "\xfb\xff\xbf"];
        yield 'binary key handle' => [rtrim(strtr(base64_encode("\x00\x01\xfe\xff"), '+/', '-_'), '='), "\x00\x01\xfe\xff"];
    }

    #[DataProvider('provideValidInput')]
    public function testDecodeToBinary(string $input, string $expected): void
    {
        self::assertSame($expected, WebsafeBase64::decodeToBinary($input));
    }

    public function testInvalidInputThrows(): void
    {
        $this->expectException(\InvalidArgumentException::class);

        WebsafeBase64::decodeToBinary('not base64!');
    }
}
