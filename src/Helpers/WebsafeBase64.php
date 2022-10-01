<?php

namespace Jbtronics\TFAWebauthn\Helpers;

class WebsafeBase64
{
    public static function decodeToBinary(string $base64): string
    {
        return base64_decode(str_replace(array('-', '_'), array('+', '/'), $base64));
    }
}