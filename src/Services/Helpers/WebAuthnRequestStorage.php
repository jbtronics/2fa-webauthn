<?php

namespace Jbtronics\TFAWebauthn\Services\Helpers;

use Symfony\Component\HttpFoundation\RequestStack;
use Symfony\Component\HttpFoundation\Session\SessionInterface;
use Webauthn\PublicKeyCredentialOptions;
use Webauthn\PublicKeyCredentialRequestOptions;

class WebAuthnRequestStorage
{
    private const AUTH_KEY = 'jbtronics_webauthn_tfa.auth_request';

    private RequestStack $requestStack;

    public function __construct(RequestStack $requestStack)
    {
        $this->requestStack = $requestStack;
    }

    public function setActiveAuthRequest(?PublicKeyCredentialRequestOptions $authRequest): void
    {
        $session = $this->requestStack->getSession();
        $session->set(self::AUTH_KEY, json_encode($authRequest, JSON_THROW_ON_ERROR));
    }

    public function getActiveAuthRequest(): ?PublicKeyCredentialRequestOptions
    {
        $session = $this->requestStack->getSession();

        $stored = $session->get(self::AUTH_KEY);
        if ($stored === null) {
            return null;
        }

        return PublicKeyCredentialRequestOptions::createFromString($stored);
    }
}