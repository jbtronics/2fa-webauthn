<?php

declare(strict_types=1);

namespace Jbtronics\TFAWebauthn\Model;

trait NoLegacyU2FKeys
{
    /**
     * @return iterable<LegacyU2FKeyInterface>
     */
    public function getLegacyU2FKeys(): iterable
    {
        // We do not have any legacy keys, so just return an empty array and they will be skipped
        return [];
    }
}
