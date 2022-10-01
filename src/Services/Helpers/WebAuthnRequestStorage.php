<?php

namespace Jbtronics\TFAWebauthn\Services\Helpers;

use Symfony\Component\HttpFoundation\RequestStack;
use Symfony\Component\HttpFoundation\Session\SessionInterface;

class WebAuthnRequestStorage
{
    private const AUTH_KEY = 'jbtronics_webauthn_tfa.auth_request';

    private RequestStack $requestStack;

    public function __construct(RequestStack $requestStack)
    {
        $this->requestStack = $requestStack;
    }

    public function setActiveAuthRequest(?\stdClass $authRequest): void
    {
        $session = $this->requestStack->getSession();
        $session->set(self::AUTH_KEY, $authRequest);
    }

    public function getActiveAuthRequest(): ?\stdClass
    {
        $session = $this->requestStack->getSession();
        return $session->get(self::AUTH_KEY);
    }
}