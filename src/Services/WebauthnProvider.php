<?php

namespace Jbtronics\TFAWebauthn\Services;

use Cose\Algorithm\Manager;
use Cose\Algorithm\Signature\ECDSA\ES256;
use Cose\Algorithm\Signature\ECDSA\ES256K;
use Cose\Algorithm\Signature\ECDSA\ES384;
use Cose\Algorithm\Signature\ECDSA\ES512;
use Cose\Algorithm\Signature\EdDSA\Ed256;
use Cose\Algorithm\Signature\EdDSA\Ed512;
use Cose\Algorithm\Signature\RSA\PS256;
use Cose\Algorithm\Signature\RSA\PS384;
use Cose\Algorithm\Signature\RSA\PS512;
use Cose\Algorithm\Signature\RSA\RS256;
use Cose\Algorithm\Signature\RSA\RS384;
use Cose\Algorithm\Signature\RSA\RS512;
use Webauthn\AttestationStatement\AttestationObjectLoader;
use Webauthn\AttestationStatement\AttestationStatementSupportManager;
use Webauthn\AttestationStatement\NoneAttestationStatementSupport;
use Webauthn\AuthenticationExtensions\ExtensionOutputCheckerHandler;
use Webauthn\AuthenticatorAssertionResponseValidator;
use Webauthn\AuthenticatorAttestationResponseValidator;
use Webauthn\PublicKeyCredentialLoader;
use Webauthn\PublicKeyCredentialRpEntity;
use Symfony\Component\EventDispatcher\EventDispatcherInterface;
use Webauthn\Event\NullEventDispatcher;

/**
 * This service provides some common services of the web-authn library which are configured by the global configuration
 */
class WebauthnProvider
{
    private PublicKeyCredentialLoader $publicKeyCredentialLoader;

    private AuthenticatorAssertionResponseValidator $assertionResponseValidator;
    private AuthenticatorAttestationResponseValidator $attestationResponseValidator;
    private PublicKeyCredentialRpEntity $rpEntity;

    public function __construct(?string $rpID, string $rpName, ?string $rpIcon,
                                EventDispatcherInterface $eventDispatcher)
    {
        //Create the RP entity
        $this->rpEntity = new PublicKeyCredentialRpEntity(
            $rpName,
            $rpID,
            $rpIcon
        );

        $this->eventDispatcher = $eventDispatcher ?? New NullEventDispatcher();

        //Create the public key credential loader
        $attestationSupportStatementManager = new AttestationStatementSupportManager();
        $this->addAttestationTypes($attestationSupportStatementManager);
        $attestationObjectLoader = new AttestationObjectLoader($attestationSupportStatementManager);

        $this->publicKeyCredentialLoader = new PublicKeyCredentialLoader($attestationObjectLoader);

        //Create the assertion response validator
        $extensionOutputCheckerHandler = new ExtensionOutputCheckerHandler();
        $coseAlgorithmManager = $this->createAlgorithmManager();

        $this->assertionResponseValidator = new AuthenticatorAssertionResponseValidator(
            publicKeyCredentialSourceRepository:  null,
            tokenBindingHandler: null,
            extensionOutputCheckerHandler: $extensionOutputCheckerHandler,
            algorithmManager:  $coseAlgorithmManager,
            eventDispatcher: $this->eventDispatcher
        );

        //Create the attestation response validator

        $this->attestationResponseValidator = new AuthenticatorAttestationResponseValidator(
            attestationStatementSupportManager: $attestationSupportStatementManager,
            publicKeyCredentialSourceRepository: null,
            tokenBindingHandler: null,
            extensionOutputCheckerHandler: $extensionOutputCheckerHandler,
            eventDispatcher: $this->eventDispatcher
        );
    }

    private function createAlgorithmManager(): Manager
    {
        return Manager::create()
            ->add(
                ES256::create(),
                ES256K::create(),
                ES384::create(),
                ES512::create(),

                RS256::create(),
                RS384::create(),
                RS512::create(),

                PS256::create(),
                PS384::create(),
                PS512::create(),

                Ed256::create(),
                Ed512::create(),
            )
            ;
    }

    private function addAttestationTypes(AttestationStatementSupportManager $attestationStatementSupportManager): void
    {
        //For now, we just support the none attestations statement type as we do not request it
        $attestationStatementSupportManager->add(new NoneAttestationStatementSupport());
    }

    public function getPublicKeyCredentialRpEntity(): PublicKeyCredentialRpEntity
    {
        return $this->rpEntity;
    }

    public function getAuthenticatorAssertionResponseValidator(): AuthenticatorAssertionResponseValidator
    {
        return $this->assertionResponseValidator;
    }

    public function getPublicKeyCredentialLoader(): PublicKeyCredentialLoader
    {
        return $this->publicKeyCredentialLoader;
    }

    public function getAuthenticatorAttestationResponseValidator(): AuthenticatorAttestationResponseValidator
    {
        return $this->attestationResponseValidator;
    }
}
