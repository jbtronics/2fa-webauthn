<?php

namespace Jbtronics\TFAWebauthn\Security\TwoFactor\Provider\Webauthn;

use Jbtronics\TFAWebauthn\Model\TwoFactorInterface;
use Jbtronics\TFAWebauthn\Services\Helpers\WebAuthnRequestStorage;
use Scheb\TwoFactorBundle\Security\TwoFactor\AuthenticationContextInterface;
use Scheb\TwoFactorBundle\Security\TwoFactor\Provider\TwoFactorFormRendererInterface;
use Scheb\TwoFactorBundle\Security\TwoFactor\Provider\TwoFactorProviderInterface;
use Webauthn\AttestationStatement\AttestationObjectLoader;
use Webauthn\PublicKeyCredentialLoader;

final readonly class TwoFactorProvider implements TwoFactorProviderInterface
{

    public function __construct(private WebauthnFormRenderer $formRenderer,
        private WebauthnAuthenticatorInterface $authenticator,
        private WebAuthnRequestStorage $requestStorage
    )
    {
    }


    public function beginAuthentication(AuthenticationContextInterface $context): bool
    {
        //Check if the user has webauthn enabled
        $user = $context->getUser();

        return $user instanceof TwoFactorInterface && $user->isWebAuthnAuthenticatorEnabled();
    }

    public function validateAuthenticationCode($user, string $authenticationCode): bool
    {
        if (!($user instanceof TwoFactorInterface)) {
            return false;
        }

        $activeAuthRequest = $this->requestStorage->getActiveAuthRequest();
        if($activeAuthRequest === null) {
            return false;
        }

        return $this->authenticator->checkAuthenticationResponse($user, $activeAuthRequest,  $authenticationCode);
    }

    public function prepareAuthentication($user): void
    {
        //We have nothing to prepare
        return;
    }

    public function getFormRenderer(): TwoFactorFormRendererInterface
    {
        return $this->formRenderer;
    }
}