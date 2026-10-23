<?php

declare(strict_types=1);

namespace Jbtronics\TFAWebauthn\Model;

/**
 * This interface is used to describe U2F key registrations which can be used for backwards compatibility.
 * If you have a legacy U2F key, you can implement this interface to allow users to use it for the new WebAuthn system.
 * This interface definition is based on TwoFactorKeyInterface from R/U2FTwoFactorBundle.
 */
interface LegacyU2FKeyInterface
{
    /**
     * The key handle, encoded as websafe base64.
     */
    public function getKeyHandle(): string;

    /**
     * The public key, encoded as standard base64.
     */
    public function getPublicKey(): string;

    public function getCertificate(): string;

    public function getCounter(): int;
}
