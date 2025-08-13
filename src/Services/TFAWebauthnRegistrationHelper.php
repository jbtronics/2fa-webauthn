<?php

namespace Jbtronics\TFAWebauthn\Services;

use Cose\Algorithms;
use Jbtronics\TFAWebauthn\Model\TwoFactorInterface;
use Jbtronics\TFAWebauthn\Services\Helpers\PSRRequestHelper;
use Jbtronics\TFAWebauthn\Services\Helpers\WebAuthnRequestStorage;
use Symfony\Bundle\SecurityBundle\Security;
use Symfony\Component\Serializer\Encoder\JsonEncode;
use Symfony\Component\Serializer\Normalizer\AbstractObjectNormalizer;
use Webauthn\AuthenticatorAttestationResponse;
use Webauthn\AuthenticatorSelectionCriteria;
use Webauthn\PublicKeyCredential;
use Webauthn\PublicKeyCredentialCreationOptions;
use Webauthn\PublicKeyCredentialDescriptor;
use Webauthn\PublicKeyCredentialParameters;
use Webauthn\PublicKeyCredentialSource;

class TFAWebauthnRegistrationHelper
{
    private int $timeout;
    private WebauthnProvider $webauthnProvider;
    private Security $security;
    private UserPublicKeyCredentialSourceRepository $keyCredentialSourceRepository;
    private PSRRequestHelper $PSRRequestHelper;
    private WebAuthnRequestStorage $webAuthnRequestStorage;

    public function __construct(int $timeout, WebauthnProvider $webauthnProvider, Security $security,
        UserPublicKeyCredentialSourceRepository $keyCredentialSourceRepository, PSRRequestHelper $PSRRequestHelper,
        WebAuthnRequestStorage $webAuthnRequestStorage)
    {
        $this->timeout = $timeout;
        $this->webauthnProvider = $webauthnProvider;
        $this->security = $security;
        $this->keyCredentialSourceRepository = $keyCredentialSourceRepository;
        $this->PSRRequestHelper = $PSRRequestHelper;
        $this->webAuthnRequestStorage = $webAuthnRequestStorage;
    }

    /**
     * Generate a new registration request for the given user and save it in the session as active registration.
     * @param  TwoFactorInterface|null  $user The user for which the registration request should be generated. If null the current user is used.
     * @return PublicKeyCredentialCreationOptions
     */
    public function generateRegistrationRequest(?TwoFactorInterface $user = null): PublicKeyCredentialCreationOptions
    {
        //If no user is given use the current user
        if ($user === null) {
            $current_user = $this->security->getUser();
            if (!$current_user instanceof TwoFactorInterface) {
                throw new \InvalidArgumentException('The current user does not implement TwoFactorInterface. You have to explicitly pass a user to this method.');
            }
            $user = $current_user;
        }

        $challenge = random_bytes(32);


        //The algorithms we allow
        $publicKeyCredentialParametersList = [
            PublicKeyCredentialParameters::create('public-key', Algorithms::COSE_ALGORITHM_ES256),
            PublicKeyCredentialParameters::create('public-key', Algorithms::COSE_ALGORITHM_ES256K),
            PublicKeyCredentialParameters::create('public-key', Algorithms::COSE_ALGORITHM_ES384),
            PublicKeyCredentialParameters::create('public-key', Algorithms::COSE_ALGORITHM_ES512),
            PublicKeyCredentialParameters::create('public-key', Algorithms::COSE_ALGORITHM_RS256),
            PublicKeyCredentialParameters::create('public-key', Algorithms::COSE_ALGORITHM_RS384),
            PublicKeyCredentialParameters::create('public-key', Algorithms::COSE_ALGORITHM_RS512),
            PublicKeyCredentialParameters::create('public-key', Algorithms::COSE_ALGORITHM_PS256),
            PublicKeyCredentialParameters::create('public-key', Algorithms::COSE_ALGORITHM_PS384),
            PublicKeyCredentialParameters::create('public-key', Algorithms::COSE_ALGORITHM_PS512),
            PublicKeyCredentialParameters::create('public-key', Algorithms::COSE_ALGORITHM_ED256),
            PublicKeyCredentialParameters::create('public-key', Algorithms::COSE_ALGORITHM_ED512),
            PublicKeyCredentialParameters::create('public-key', Algorithms::COSE_ALGORITHM_EDDSA),
        ];

        //Exclude all existing credentials
        $excludedCredentials = array_map(
            static function (PublicKeyCredentialSource $credential): PublicKeyCredentialDescriptor {
                return $credential->getPublicKeyCredentialDescriptor();
            },
            $this->keyCredentialSourceRepository->findAllForUserEntity($user->getWebAuthnUser())
        );

        $data = PublicKeyCredentialCreationOptions::create(
            rp: $this->webauthnProvider->getPublicKeyCredentialRpEntity(),
            user: $user->getWebAuthnUser(),
            challenge:  $challenge,
            pubKeyCredParams:  $publicKeyCredentialParametersList,
            authenticatorSelection: AuthenticatorSelectionCriteria::create(),
            attestation: PublicKeyCredentialCreationOptions::ATTESTATION_CONVEYANCE_PREFERENCE_NONE,
            excludeCredentials: $excludedCredentials,
            timeout: $this->timeout,
        );

        //Save creation options in the session, so it can be used for validation later
        $this->webAuthnRequestStorage->setActiveRegistrationRequest($data);

        return $data;
    }

    /**
     * Generate a new registration request for the given user and returns it as JSON, so that it can be passed to the browser.
     * @param  TwoFactorInterface|null  $user
     * @return string The registration request as JSON
     */
    public function generateRegistrationRequestAsJSON(?TwoFactorInterface $user = null): string
    {
        return $this->webauthnProvider->getWebauthnSerializer()->serialize(
            $this->generateRegistrationRequest($user),
            'json',
            [
                AbstractObjectNormalizer::SKIP_NULL_VALUES => true, // Highly recommended!
                JsonEncode::OPTIONS => JSON_THROW_ON_ERROR, // Optional
            ]
        );
    }

    /**
     * Validate the given registration response and returns the new key.
     * If the response is invalid an exception is thrown.
     * @param  string  $jsonResponse The json encoded response from the browser
     * @return PublicKeyCredentialSource The credential returned from the browser
     */
    public function checkRegistrationResponse(string $jsonResponse): PublicKeyCredentialSource
    {
        $serializer = $this->webauthnProvider->getWebauthnSerializer();
        $publicKeyCredential = $serializer->deserialize($jsonResponse, PublicKeyCredential::class, 'json');
        $authenticatorAttestationResponse = $publicKeyCredential->response;

        if (!$authenticatorAttestationResponse instanceof AuthenticatorAttestationResponse) {
            throw new \RuntimeException('The given response is not an AuthenticatorAttestationResponse!');
        }

        $serverRequest = $this->PSRRequestHelper->getCurrentRequestAsPSR7();
        if ($serverRequest === null) {
            throw new \RuntimeException('Could not get the current request!');
        }

        $activeRegistration = $this->webAuthnRequestStorage->getActiveRegistrationRequest();
        if ($activeRegistration === null) {
            throw new \RuntimeException('No active registration request found!');
        }

        return $this->webauthnProvider->getAuthenticatorAttestationResponseValidator()->check(
            authenticatorAttestationResponse:  $authenticatorAttestationResponse,
            publicKeyCredentialCreationOptions:  $activeRegistration,
            host: $serverRequest->getUri()->getHost(),
        );
    }


}