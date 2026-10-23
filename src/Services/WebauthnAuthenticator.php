<?php

declare(strict_types=1);

namespace Jbtronics\TFAWebauthn\Services;

use Jbtronics\TFAWebauthn\Model\TwoFactorInterface;
use Jbtronics\TFAWebauthn\Security\TwoFactor\Provider\Webauthn\WebauthnAuthenticatorInterface;
use Jbtronics\TFAWebauthn\Services\Helpers\PSRRequestHelper;
use Jbtronics\TFAWebauthn\Services\Helpers\U2FAppIDProvider;
use Psr\Log\LoggerInterface;
use Psr\Log\NullLogger;
use Symfony\Component\Serializer\Exception\ExceptionInterface as SerializerExceptionInterface;
use Webauthn\AuthenticationExtensions\AuthenticationExtension;
use Webauthn\AuthenticatorAssertionResponse;
use Webauthn\PublicKeyCredential;
use Webauthn\PublicKeyCredentialDescriptor;
use Webauthn\PublicKeyCredentialRequestOptions;
use Webauthn\PublicKeyCredentialSource;

readonly class WebauthnAuthenticator implements WebauthnAuthenticatorInterface
{
    private LoggerInterface $logger;

    /**
     * @param positive-int $timeout
     */
    public function __construct(
        private U2FAppIDProvider $u2FAppIDProvider,
        private UserPublicKeyCredentialSourceRepository $publicKeyCredentialSourceRepository,
        private WebauthnProvider $webauthnProvider,
        private PSRRequestHelper $PSRRequestHelper,
        private int $timeout,
        private ?string $rpID,
        ?LoggerInterface $logger = null,
        private string $requireUserVerification = PublicKeyCredentialRequestOptions::USER_VERIFICATION_REQUIREMENT_DISCOURAGED,
    ) {
        $this->logger = $logger ?? new NullLogger();
    }

    public function generateAuthenticationRequest(?TwoFactorInterface $user = null): PublicKeyCredentialRequestOptions
    {
        if (null === $user) {
            throw new \LogicException('You have to pass a user to this method!');
        }

        // Retrieve the registered keys for the user
        $allowedCredentials = array_map(
            static fn (PublicKeyCredentialSource $credential): PublicKeyCredentialDescriptor => $credential->getPublicKeyCredentialDescriptor(),
            $this->publicKeyCredentialSourceRepository->findAllForUserEntity($user->getWebAuthnUser())
        );

        return PublicKeyCredentialRequestOptions::create(
            challenge: random_bytes(32),
            rpId: $this->rpID,
            allowCredentials: $allowedCredentials,
            userVerification: $this->requireUserVerification,
            timeout: $this->timeout,
            // Add the U2F appID extension for backward compatibility
            extensions: [
                AuthenticationExtension::create('appid', $this->u2FAppIDProvider->getAppID()),
            ],
        );
    }

    public function checkAuthenticationResponse(TwoFactorInterface $user, PublicKeyCredentialRequestOptions $request, string $response): bool
    {
        // Check that the JSON encoded response is valid
        try {
            $publicKeyCredential = $this->webauthnProvider->getWebauthnSerializer()->deserialize($response, PublicKeyCredential::class, 'json');
        } catch (SerializerExceptionInterface $exception) {
            $this->logger->error('Webauthn authentication failed: Unable to load JSON data. Message: '.$exception->getMessage(), [
                'exception' => $exception,
            ]);

            return false;
        }

        // The serializer falls back to returning the decoded array if the data does not look like a credential
        if (!$publicKeyCredential instanceof PublicKeyCredential) {
            $this->logger->error('Webauthn authentication failed: The given response is not a webauthn credential!');

            return false;
        }

        // Find the credential source for the given credential id
        $publicKeyCredentialSource = $this->publicKeyCredentialSourceRepository->findOneByCredentialId($publicKeyCredential->rawId);
        if (null === $publicKeyCredentialSource) {
            $this->logger->error('Webauthn authentication failed: No credential source found for the given credential id!');

            return false;
        }

        $authenticatorAssertionResponse = $publicKeyCredential->response;
        if (!$authenticatorAssertionResponse instanceof AuthenticatorAssertionResponse) {
            $this->logger->error('Webauthn authentication failed: The given response is not an AuthenticatorAssertionResponse!');

            return false;
        }

        // We need a PSR conform version of our current request, so the webauthn library can get the currently used hostname (needed in case no rpId was explicitly set)
        $psrRequest = $this->PSRRequestHelper->getCurrentRequestAsPSR7();
        if (null === $psrRequest) {
            throw new \RuntimeException('Could not get current request as PSR7 request!');
        }

        try {
            // The first parameter was renamed from "publicKeyCredentialSource" to "credentialRecord" in
            // web-auth/webauthn-lib 5.3 (a PublicKeyCredentialSource is still accepted there, just deprecated).
            // Pass it positionally so the call works with both the old and the new parameter name.
            $this->webauthnProvider->getAuthenticatorAssertionResponseValidator()->check(
                $publicKeyCredentialSource,
                authenticatorAssertionResponse: $authenticatorAssertionResponse,
                publicKeyCredentialRequestOptions: $request,
                host: $psrRequest->getUri()->getHost(),
                userHandle: $user->getWebAuthnUser()->id,
            );

            return true;
        } catch (\Throwable $e) {
            // If any exception happens during the check, the check failed, and we do not log the user in
            $this->logger->error('Webauthn authentication failed: '.$e->getMessage(), [
                'exception' => $e,
            ]);

            return false;
        }
    }
}
