<?php

declare(strict_types=1);

namespace Jbtronics\TFAWebauthn\Services\Helpers;

use Jbtronics\TFAWebauthn\Services\WebauthnProvider;
use Symfony\Component\HttpFoundation\RequestStack;
use Symfony\Component\Serializer\Encoder\JsonDecode;
use Symfony\Component\Serializer\Encoder\JsonEncode;
use Symfony\Component\Serializer\Normalizer\AbstractObjectNormalizer;
use Webauthn\PublicKeyCredentialCreationOptions;
use Webauthn\PublicKeyCredentialOptions;
use Webauthn\PublicKeyCredentialRequestOptions;

/**
 * This service stores the authentication and registration requests in the session so that they can be retrieved later,
 * for validation.
 */
class WebAuthnRequestStorage
{
    private const AUTH_KEY = 'jbtronics_webauthn_tfa.auth_request';
    private const REG_KEY = 'jbtronics_webauthn_tfa.reg_request';

    public function __construct(private readonly RequestStack $requestStack, private readonly WebauthnProvider $webauthnProvider)
    {
    }

    /**
     * Stores the active PublicKeyCredentialRequestOptions in the session, or clears it if null is given.
     */
    public function setActiveAuthRequest(?PublicKeyCredentialRequestOptions $authRequest): void
    {
        $this->store(self::AUTH_KEY, $authRequest);
    }

    /**
     * Returns the active PublicKeyCredentialRequestOptions from the session, or null if none was saved before.
     */
    public function getActiveAuthRequest(): ?PublicKeyCredentialRequestOptions
    {
        return $this->load(self::AUTH_KEY, PublicKeyCredentialRequestOptions::class);
    }

    /**
     * Stores the active PublicKeyCredentialCreationOptions in the session, or clears it if null is given.
     */
    public function setActiveRegistrationRequest(?PublicKeyCredentialCreationOptions $registrationRequest): void
    {
        $this->store(self::REG_KEY, $registrationRequest);
    }

    /**
     * Returns the active PublicKeyCredentialCreationOptions from the session, or null if none was saved before.
     */
    public function getActiveRegistrationRequest(): ?PublicKeyCredentialCreationOptions
    {
        return $this->load(self::REG_KEY, PublicKeyCredentialCreationOptions::class);
    }

    private function store(string $key, ?PublicKeyCredentialOptions $options): void
    {
        $session = $this->requestStack->getSession();

        if (null === $options) {
            $session->remove($key);

            return;
        }

        $session->set($key, $this->webauthnProvider->getWebauthnSerializer()->serialize($options, 'json', [
            AbstractObjectNormalizer::SKIP_NULL_VALUES => true,
            JsonEncode::OPTIONS => \JSON_THROW_ON_ERROR,
        ]));
    }

    /**
     * @template T of PublicKeyCredentialOptions
     *
     * @param class-string<T> $class
     *
     * @return T|null
     */
    private function load(string $key, string $class): ?PublicKeyCredentialOptions
    {
        $stored = $this->requestStack->getSession()->get($key);
        if (!\is_string($stored)) {
            return null;
        }

        $options = $this->webauthnProvider->getWebauthnSerializer()->deserialize($stored, $class, 'json', [
            JsonDecode::OPTIONS => \JSON_THROW_ON_ERROR,
        ]);

        return $options instanceof $class ? $options : null;
    }
}
