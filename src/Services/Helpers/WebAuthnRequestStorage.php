<?php

namespace Jbtronics\TFAWebauthn\Services\Helpers;

use Jbtronics\TFAWebauthn\Services\WebauthnProvider;
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


    public function __construct(private readonly RequestStack $requestStack, private readonly WebauthnProvider $webauthnProvider)
    {
    }

    /**
     * This method stores the active PublicKeyCredentialRequestOptions in the session
     * @param  PublicKeyCredentialRequestOptions|null  $authRequest
     * @return void
     */
    public function setActiveAuthRequest(?PublicKeyCredentialRequestOptions $authRequest): void
    {
        $serializer = $this->webauthnProvider->getWebauthnSerializer();

        $session = $this->requestStack->getSession();
        $session->set(self::AUTH_KEY, $serializer->serialize($authRequest, 'json', [
            'skip_null_values' => true, // Highly recommended!
            'json_encode_options' => JSON_THROW_ON_ERROR
        ]));
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

        // Deserialize the stored JSON string into a PublicKeyCredentialRequestOptions object
        return $this->webauthnProvider->getWebauthnSerializer()->deserialize($stored, PublicKeyCredentialRequestOptions::class, 'json', [
            'json_decode_options' => JSON_THROW_ON_ERROR
        ]);
    }

    /**
     * Save the active PublicKeyCredentialCreationOptions in the session
     * @param  PublicKeyCredentialCreationOptions|null  $registrationRequest
     * @return void
     * @throws \JsonException
     */
    public function setActiveRegistrationRequest(?PublicKeyCredentialCreationOptions $registrationRequest): void
    {
        $serializer = $this->webauthnProvider->getWebauthnSerializer();
        $session = $this->requestStack->getSession();

        $session->set(self::REG_KEY, $serializer->serialize($registrationRequest, 'json', [
            'skip_null_values' => true, // Highly recommended!
            'json_encode_options' => JSON_THROW_ON_ERROR
        ]));
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

        return $this->webauthnProvider->getWebauthnSerializer()->deserialize($stored, PublicKeyCredentialCreationOptions::class, 'json', [
            'json_decode_options' => JSON_THROW_ON_ERROR
        ]);
    }


}