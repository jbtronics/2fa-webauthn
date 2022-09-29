<?php

namespace jbtronics\TFAWebauthn\Services\Helpers;

class WebsafeBase64
{
    public static function decodeToBinary(string $base64): string
    {
        return str_replace(array('-', '_'), array('+', '/'), $base64);
    }
}