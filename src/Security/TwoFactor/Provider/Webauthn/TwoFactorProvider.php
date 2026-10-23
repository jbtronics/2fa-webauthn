<?php

declare(strict_types=1);

namespace Jbtronics\TFAWebauthn\Security\TwoFactor\Provider\Webauthn;

use Jbtronics\TFAWebauthn\Model\TwoFactorInterface;
use Jbtronics\TFAWebauthn\Services\Helpers\WebAuthnRequestStorage;
use Scheb\TwoFactorBundle\Security\TwoFactor\AuthenticationContextInterface;
use Scheb\TwoFactorBundle\Security\TwoFactor\Provider\TwoFactorFormRendererInterface;
use Scheb\TwoFactorBundle\Security\TwoFactor\Provider\TwoFactorProviderInterface;

final readonly class TwoFactorProvider implements TwoFactorProviderInterface
{
    public function __construct(
        private TwoFactorFormRendererInterface $formRenderer,
        private WebauthnAuthenticatorInterface $authenticator,
        private WebAuthnRequestStorage $requestStorage,
    ) {
    }

    public function beginAuthentication(AuthenticationContextInterface $context): bool
    {
        $user = $context->getUser();

        return $user instanceof TwoFactorInterface && $user->isWebAuthnAuthenticatorEnabled();
    }

    /**
     * The authentication request is generated when the form is rendered, nothing to prepare here.
     * Will be part of TwoFactorProviderInterface in scheb/2fa-bundle 9.
     */
    public function needsPreparation(): bool
    {
        return false;
    }

    public function prepareAuthentication(object $user): void
    {
    }

    public function validateAuthenticationCode(object $user, string $authenticationCode): bool
    {
        if (!$user instanceof TwoFactorInterface) {
            return false;
        }

        $activeAuthRequest = $this->requestStorage->getActiveAuthRequest();
        if (null === $activeAuthRequest) {
            return false;
        }

        return $this->authenticator->checkAuthenticationResponse($user, $activeAuthRequest, $authenticationCode);
    }

    public function getFormRenderer(): TwoFactorFormRendererInterface
    {
        return $this->formRenderer;
    }
}
