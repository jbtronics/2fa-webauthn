<?php

namespace Jbtronics\TFAWebauthn\Services;

use Jbtronics\TFAWebauthn\Model\TwoFactorInterface;
use Jbtronics\TFAWebauthn\Security\TwoFactor\Provider\Webauthn\WebauthnAuthenticatorInterface;
use jbtronics\TFAWebauthn\Services\Helpers\PSRRequestHelper;
use Jbtronics\TFAWebauthn\Services\Helpers\U2FAppIDProvider;
use Psr\Log\LoggerInterface;
use Symfony\Component\Serializer\Exception\ExceptionInterface;
use Webauthn\AuthenticationExtensions\AuthenticationExtension;
use Webauthn\AuthenticatorAssertionResponse;
use Webauthn\PublicKeyCredential;
use Webauthn\PublicKeyCredentialDescriptor;
use Webauthn\PublicKeyCredentialRequestOptions;
use Webauthn\PublicKeyCredentialSource;

readonly class WebauthnAuthenticator implements WebauthnAuthenticatorInterface
{

    public function __construct(private U2FAppIDProvider $u2FAppIDProvider,
        private UserPublicKeyCredentialSourceRepository $publicKeyCredentialSourceRepository,
        private WebauthnProvider $webauthnProvider,
        private PSRRequestHelper $PSRRequestHelper,
        private int $timeout,
        private ?string $rpID,
        private ?LoggerInterface $logger = null,
        private string $requireUserVerification = "discouraged"
    )
    {
    }

    public function generateAuthenticationRequest(?TwoFactorInterface $user = null): PublicKeyCredentialRequestOptions
    {
        if ($user === null) {
            throw new \LogicException('You have to pass a user to this method!');
        }

        //Retrieve the registered keys for the user
        $allowedCredentials = array_map(
            static function (PublicKeyCredentialSource $credential): PublicKeyCredentialDescriptor {
                return $credential->getPublicKeyCredentialDescriptor();
            },
            $this->publicKeyCredentialSourceRepository->findAllForUserEntity($user->getWebAuthnUser())
        );

        //Generate a random challenge
        $challenge = random_bytes(32);

        //Add the U2F appID extension for backward compatibility
        $extensions =  [
            new AuthenticationExtension('appid', $this->u2FAppIDProvider->getAppID())
        ];

        //Set options
        $request = PublicKeyCredentialRequestOptions::create(
            challenge: $challenge,
            rpId: $this->rpID,
            allowCredentials: $allowedCredentials,
            userVerification: $this->requireUserVerification,
            timeout: $this->timeout,
            extensions: $extensions,
        );

        return $request;
    }

    public function checkAuthenticationResponse(TwoFactorInterface $user, PublicKeyCredentialRequestOptions $request, string $response): bool
    {
        $publicKeySerializer = $this->webauthnProvider->getWebauthnSerializer();
        $validator = $this->webauthnProvider->getAuthenticatorAssertionResponseValidator();

        //Check that the JSON encoded response is valid
        try {
            $publicKeyCredential = $publicKeySerializer->deserialize($response, PublicKeyCredential::class, 'json');
        } catch (ExceptionInterface $exception) {
            if ($this->logger) {
                $this->logger->error('Webauthn authentication failed: Unable to load JSON data. Message: ' . $exception->getMessage(), [
                    'exception' => $exception,
                ]);
            }
            return false;
        }

        //Find the credential source for the given credential id
        $publicKeyCredentialSource = $this->publicKeyCredentialSourceRepository->findOneByCredentialId($publicKeyCredential->rawId);

        if ($publicKeyCredentialSource === null) {
            if ($this->logger) {
                $this->logger->error('Webauthn authentication failed: No credential source found for the given credential id!');
            }
            return false;
        }

        $authenticatorAssertionResponse = $publicKeyCredential->response;
        if (!$authenticatorAssertionResponse instanceof AuthenticatorAssertionResponse) {
            if ($this->logger) {
                $this->logger->error('Webauthn authentication failed: The given response is not an AuthenticatorAssertionResponse!');
            }
            return false;
        }

        //We need a PSR conform version of our current request, so the webauthn library can get the currently used hostname (needed in case no rpId was explicitly set)
        $psrRequest = $this->PSRRequestHelper->getCurrentRequestAsPSR7();

        if ($psrRequest === null) {
            throw new \RuntimeException('Could not get current request as PSR7 request!');
        }

        $host = $psrRequest->getUri()->getHost();

        //Do the check
        try {
            $publicKeyCredentialSource = $validator->check(
                publicKeyCredentialSource: $publicKeyCredentialSource,
                authenticatorAssertionResponse:  $authenticatorAssertionResponse,
                publicKeyCredentialRequestOptions:  $request,
                host: $host,
                userHandle: $user->getWebAuthnUser()->id
            );

            return true;
        } catch (\Throwable $e) {
            //If any exception happens during the check, the check failed, and we do not log the user in

            if ($this->logger) {
                $this->logger->error('Webauthn authentication failed: ' . $e->getMessage(), [
                    'exception' => $e,
                ]);
            }

            return false;
        }
    }
}