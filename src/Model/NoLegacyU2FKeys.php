<?php

namespace Jbtronics\TFAWebauthn\Model;

trait NoLegacyU2FKeys
{
    public function getLegacyU2FKeys(): iterable
    {
        //We do not have any legacy keys, so just return an empty array and they will be skipped
        return [];
    }
}