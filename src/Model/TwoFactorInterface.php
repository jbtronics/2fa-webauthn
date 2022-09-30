<?php

namespace Jbtronics\TFAWebauthn\Model;

use Jbtronics\TFAWebauthn\Model\Legacy\LegacyU2FKeyInterface;

/**
 * A user has to implement this interface to allow 2FA with webauthn
 */
interface TwoFactorInterface
{
    /**
     * @return bool The name of the user
     */
    public function isWebAuthnAuthenticatorEnabled(): bool;

    /**
     * @return iterable<LegacyU2FKeyInterface> The webauthn keys of the user
     */
    public function getLegacyU2FKeys(): iterable;

}