<?php

declare(strict_types=1);

namespace Jbtronics\TFAWebauthn\Services;

use Cose\Algorithms;
use Jbtronics\TFAWebauthn\Model\TwoFactorInterface;
use Jbtronics\TFAWebauthn\Services\Helpers\PSRRequestHelper;
use Jbtronics\TFAWebauthn\Services\Helpers\WebAuthnRequestStorage;
use Symfony\Bundle\SecurityBundle\Security;
use Symfony\Component\Serializer\Encoder\JsonEncode;
use Symfony\Component\Serializer\Exception\ExceptionInterface as SerializerExceptionInterface;
use Symfony\Component\Serializer\Normalizer\AbstractObjectNormalizer;
use Webauthn\AuthenticatorAttestationResponse;
use Webauthn\AuthenticatorSelectionCriteria;
use Webauthn\PublicKeyCredential;
use Webauthn\PublicKeyCredentialCreationOptions;
use Webauthn\PublicKeyCredentialDescriptor;
use Webauthn\PublicKeyCredentialParameters;
use Webauthn\PublicKeyCredentialSource;

readonly class TFAWebauthnRegistrationHelper
{
    /**
     * @param positive-int $timeout
     */
    public function __construct(
        private int $timeout,
        private WebauthnProvider $webauthnProvider,
        private Security $security,
        private UserPublicKeyCredentialSourceRepository $keyCredentialSourceRepository,
        private PSRRequestHelper $PSRRequestHelper,
        private WebAuthnRequestStorage $requestStorage,
    ) {
    }

    /**
     * Generate a new registration request for the given user and save it in the session as active registration.
     *
     * @param TwoFactorInterface|null $user The user for which the registration request should be generated. If null the current user is used.
     */
    public function generateRegistrationRequest(?TwoFactorInterface $user = null): PublicKeyCredentialCreationOptions
    {
        // If no user is given use the current user
        if (null === $user) {
            $current_user = $this->security->getUser();
            if (!$current_user instanceof TwoFactorInterface) {
                throw new \InvalidArgumentException('The current user does not implement TwoFactorInterface. You have to explicitly pass a user to this method.');
            }
            $user = $current_user;
        }

        $challenge = random_bytes(32);

        // The algorithms we allow
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

        // Exclude all existing credentials
        $excludedCredentials = array_map(
            static fn (PublicKeyCredentialSource $credential): PublicKeyCredentialDescriptor => $credential->getPublicKeyCredentialDescriptor(),
            $this->keyCredentialSourceRepository->findAllForUserEntity($user->getWebAuthnUser())
        );

        $data = PublicKeyCredentialCreationOptions::create(
            rp: $this->webauthnProvider->getPublicKeyCredentialRpEntity(),
            user: $user->getWebAuthnUser(),
            challenge: $challenge,
            pubKeyCredParams: $publicKeyCredentialParametersList,
            authenticatorSelection: AuthenticatorSelectionCriteria::create(),
            attestation: PublicKeyCredentialCreationOptions::ATTESTATION_CONVEYANCE_PREFERENCE_NONE,
            excludeCredentials: $excludedCredentials,
            timeout: $this->timeout,
        );

        // Save creation options in the session, so it can be used for validation later
        $this->requestStorage->setActiveRegistrationRequest($data);

        return $data;
    }

    /**
     * Generate a new registration request for the given user and returns it as JSON, so that it can be passed to the browser.
     *
     * @return string The registration request as JSON
     */
    public function generateRegistrationRequestAsJSON(?TwoFactorInterface $user = null): string
    {
        return $this->webauthnProvider->getWebauthnSerializer()->serialize(
            $this->generateRegistrationRequest($user),
            'json',
            [
                AbstractObjectNormalizer::SKIP_NULL_VALUES => true,
                JsonEncode::OPTIONS => \JSON_THROW_ON_ERROR,
            ]
        );
    }

    /**
     * Validate the given registration response and returns the new key.
     * If the response is invalid an exception is thrown.
     *
     * @param string $jsonResponse The json encoded response from the browser
     *
     * @return PublicKeyCredentialSource The credential returned from the browser
     */
    public function checkRegistrationResponse(string $jsonResponse): PublicKeyCredentialSource
    {
        $serializer = $this->webauthnProvider->getWebauthnSerializer();
        try {
            $publicKeyCredential = $serializer->deserialize($jsonResponse, PublicKeyCredential::class, 'json');
        } catch (SerializerExceptionInterface $exception) {
            throw new \RuntimeException('The given response is not valid JSON encoded webauthn credential!', 0, $exception);
        }

        // The serializer falls back to returning the decoded array if the data does not look like a credential
        if (!$publicKeyCredential instanceof PublicKeyCredential) {
            throw new \RuntimeException('The given response is not a webauthn credential!');
        }

        $authenticatorAttestationResponse = $publicKeyCredential->response;

        if (!$authenticatorAttestationResponse instanceof AuthenticatorAttestationResponse) {
            throw new \RuntimeException('The given response is not an AuthenticatorAttestationResponse!');
        }

        $serverRequest = $this->PSRRequestHelper->getCurrentRequestAsPSR7();
        if (null === $serverRequest) {
            throw new \RuntimeException('Could not get the current request!');
        }

        $activeRegistration = $this->requestStorage->getActiveRegistrationRequest();
        if (null === $activeRegistration) {
            throw new \RuntimeException('No active registration request found!');
        }

        $credential = $this->webauthnProvider->getAuthenticatorAttestationResponseValidator()->check(
            authenticatorAttestationResponse: $authenticatorAttestationResponse,
            publicKeyCredentialCreationOptions: $activeRegistration,
            host: $serverRequest->getUri()->getHost(),
        );

        // On web-auth/webauthn-lib < 5.3, check() already returns a PublicKeyCredentialSource.
        if ($credential instanceof PublicKeyCredentialSource) {
            return $credential;
        }

        // Since web-auth/webauthn-lib 5.3, check() returns a CredentialRecord instead (PublicKeyCredentialSource is
        // now deprecated and will be removed in 6.0). Wrap it back using the library-provided bridge, so consuming
        // applications relying on PublicKeyCredentialSource keep working.
        return PublicKeyCredentialSource::fromCredentialRecord($credential);
    }
}
