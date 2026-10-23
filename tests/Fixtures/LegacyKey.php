<?php

declare(strict_types=1);

namespace Jbtronics\TFAWebauthn\Tests\Fixtures;

use Jbtronics\TFAWebauthn\Model\LegacyU2FKeyInterface;

final readonly class LegacyKey implements LegacyU2FKeyInterface
{
    public function __construct(private string $keyHandle, private string $publicKey)
    {
    }

    public function getKeyHandle(): string
    {
        return $this->keyHandle;
    }

    public function getPublicKey(): string
    {
        return $this->publicKey;
    }

    public function getCertificate(): string
    {
        return '';
    }

    public function getCounter(): string
    {
        return '0';
    }
}
