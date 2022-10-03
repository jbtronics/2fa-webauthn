<?php

namespace Jbtronics\TFAWebauthn\Model;

use Jbtronics\TFAWebauthn\Model\Legacy\LegacyU2FKeyInterface;
use Webauthn\PublicKeyCredentialUserEntity;

/**
 * A user has to implement this interface to allow 2FA with webauthn
 */
interface TwoFactorInterface
{
    /**
     * Determines whether the user has 2FA using Webauthn enabled
     * @return bool True if the webauthn 2FA is enabled, false otherwise
     */
    public function isWebAuthnAuthenticatorEnabled(): bool;

    /**
     * Returns a list of all legacy U2F keys.
     * Return an empty array, if this user does not have any legacy U2F keys.
     * @return iterable<LegacyU2FKeyInterface>
     */
    public function getLegacyU2FKeys(): iterable;

    /**
     * Returns the webauthn user entity that should be used for this user.
     * @return PublicKeyCredentialUserEntity
     */
    public function getWebAuthnUser(): PublicKeyCredentialUserEntity;

}