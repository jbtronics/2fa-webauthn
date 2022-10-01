<?php

namespace Jbtronics\TFAWebauthn\Security\TwoFactor\Provider\Webauthn;

use Jbtronics\TFAWebauthn\Model\TwoFactorInterface;
use Jbtronics\TFAWebauthn\Services\Helpers\WebAuthnRequestStorage;
use Scheb\TwoFactorBundle\Security\TwoFactor\AuthenticationContextInterface;
use Scheb\TwoFactorBundle\Security\TwoFactor\Provider\TwoFactorFormRendererInterface;
use Scheb\TwoFactorBundle\Security\TwoFactor\Provider\TwoFactorProviderInterface;

final class TwoFactorProvider implements TwoFactorProviderInterface
{
    private WebauthnFormRenderer $formRenderer;
    private WebauthnAuthenticatorInterface $authenticator;
    private WebAuthnRequestStorage $requestStorage;

    public function __construct(WebauthnFormRenderer $formRenderer, WebauthnAuthenticatorInterface $authenticator, WebAuthnRequestStorage $webAuthnRequestStorage)
    {
        $this->formRenderer = $formRenderer;
        $this->authenticator = $authenticator;
        $this->requestStorage = $webAuthnRequestStorage;
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

        //Decode our authentication code
        $authCode = json_decode($authenticationCode,null, 512, JSON_THROW_ON_ERROR);

        $activeAuthRequest = $this->requestStorage->getActiveAuthRequest();
        if($activeAuthRequest === null) {
            return false;
        }

        return $this->authenticator->checkRequest($user, $activeAuthRequest,  $authCode);
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