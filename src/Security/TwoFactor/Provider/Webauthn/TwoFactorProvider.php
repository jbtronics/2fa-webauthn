<?php

namespace jbtronics\TFAWebauthn\Security\TwoFactor\Provider;

use jbtronics\TFAWebauthn\Model\TwoFactorInterface;
use Scheb\TwoFactorBundle\Security\TwoFactor\AuthenticationContextInterface;
use Scheb\TwoFactorBundle\Security\TwoFactor\Provider\TwoFactorFormRendererInterface;
use Scheb\TwoFactorBundle\Security\TwoFactor\Provider\TwoFactorProviderInterface;

class TwoFactorProvider implements TwoFactorProviderInterface
{

    public function beginAuthentication(AuthenticationContextInterface $context): bool
    {
        //Check if the user has webauthn enabled
        $user = $context->getUser();

        return $user instanceof TwoFactorInterface && $user->isWebAuthnAuthenticatorEnabled();
    }

    public function prepareAuthentication(object $user): void
    {
        //We have nothing to prepare
        return;
    }

    public function validateAuthenticationCode(object $user, string $authenticationCode): bool
    {
        // TODO: Implement validateAuthenticationCode() method.
    }

    public function getFormRenderer(): TwoFactorFormRendererInterface
    {
        // TODO: Implement getFormRenderer() method.
    }
}