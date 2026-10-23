<?php

declare(strict_types=1);

namespace Jbtronics\TFAWebauthn\Helpers;

class WebsafeBase64
{
    /**
     * Decodes a (padded or unpadded) base64url string to binary. Invalid characters are ignored.
     */
    public static function decodeToBinary(string $base64): string
    {
        $decoded = base64_decode(strtr($base64, '-_', '+/'));

        return false === $decoded ? '' : $decoded;
    }
}
