<?php

namespace Jbtronics\TFAWebauthn\Services\Helpers;

use Symfony\Component\HttpFoundation\RequestStack;
use Webauthn\PublicKeyCredentialCreationOptions;
use Webauthn\PublicKeyCredentialRequestOptions;

/**
 * This service stores the authentication and registration requests in the session so that they can be retrieved later,
 * for validation
 */
class WebAuthnRequestStorage
{
    private const AUTH_KEY = 'jbtronics_webauthn_tfa.auth_request';
    private const REG_KEY = 'jbtronics_webauthn_tfa.reg_request';

    private RequestStack $requestStack;

    public function __construct(RequestStack $requestStack)
    {
        $this->requestStack = $requestStack;
    }

    /**
     * This method stores the active PublicKeyCredentialRequestOptions in the session
     * @param  PublicKeyCredentialRequestOptions|null  $authRequest
     * @return void
     */
    public function setActiveAuthRequest(?PublicKeyCredentialRequestOptions $authRequest): void
    {
        $session = $this->requestStack->getSession();
        $session->set(self::AUTH_KEY, json_encode($authRequest, JSON_THROW_ON_ERROR));
    }

    /**
     * This method returns the active PublicKeyCredentialRequestOptions from the session, or null if
     * @return PublicKeyCredentialRequestOptions|null
     */
    public function getActiveAuthRequest(): ?PublicKeyCredentialRequestOptions
    {
        $session = $this->requestStack->getSession();

        $stored = $session->get(self::AUTH_KEY);
        if ($stored === null) {
            return null;
        }

        return PublicKeyCredentialRequestOptions::createFromString($stored);
    }

    /**
     * Save the active PublicKeyCredentialCreationOptions in the session
     * @param  PublicKeyCredentialCreationOptions|null  $registrationRequest
     * @return void
     * @throws \JsonException
     */
    public function setActiveRegistrationRequest(?PublicKeyCredentialCreationOptions $registrationRequest): void
    {
        $session = $this->requestStack->getSession();
        $session->set(self::REG_KEY, json_encode($registrationRequest, JSON_THROW_ON_ERROR));
    }

    /**
     * Retrieve the active PublicKeyCredentialCreationOptions from the session, or null if now was saved before
     * @return PublicKeyCredentialCreationOptions|null
     */
    public function getActiveRegistrationRequest(): ?PublicKeyCredentialCreationOptions
    {
        $session = $this->requestStack->getSession();

        $stored = $session->get(self::REG_KEY);
        if ($stored === null) {
            return null;
        }

        return PublicKeyCredentialCreationOptions::createFromString($stored);
    }


}