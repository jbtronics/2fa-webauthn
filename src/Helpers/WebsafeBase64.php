<?php

declare(strict_types=1);

namespace Jbtronics\TFAWebauthn\Helpers;

final class WebsafeBase64
{
    /**
     * Decodes a (padded or unpadded) base64url string to binary.
     *
     * @throws \InvalidArgumentException if the input is not valid base64url
     */
    public static function decodeToBinary(string $base64): string
    {
        $decoded = base64_decode(strtr($base64, '-_', '+/'), true);
        if (false === $decoded) {
            throw new \InvalidArgumentException('The given string is not valid base64url.');
        }

        return $decoded;
    }
}
