<?php

namespace Jbtronics\TFAWebauthn\Services;

use Cose\Algorithm\Manager;
use Webauthn\AttestationStatement\AttestationObjectLoader;
use Webauthn\AttestationStatement\AttestationStatement;
use Webauthn\AttestationStatement\AttestationStatementSupport;
use Webauthn\AttestationStatement\AttestationStatementSupportManager;
use Webauthn\AttestationStatement\NoneAttestationStatementSupport;
use Webauthn\AuthenticationExtensions\ExtensionOutputCheckerHandler;
use Webauthn\AuthenticatorAssertionResponseValidator;
use Webauthn\AuthenticatorAttestationResponseValidator;
use Webauthn\PublicKeyCredentialLoader;
use Webauthn\PublicKeyCredentialRpEntity;
use Webauthn\PublicKeyCredentialSourceRepository;
use Webauthn\TokenBinding\TokenBindingNotSupportedHandler;
use Cose\Algorithm\Signature\ECDSA\ES256;
use Cose\Algorithm\Signature\ECDSA\ES256K;
use Cose\Algorithm\Signature\ECDSA\ES384;
use Cose\Algorithm\Signature\ECDSA\ES512;
use Cose\Algorithm\Signature\EdDSA\ED256;
use Cose\Algorithm\Signature\EdDSA\ED512;
use Cose\Algorithm\Signature\RSA\PS256;
use Cose\Algorithm\Signature\RSA\PS384;
use Cose\Algorithm\Signature\RSA\PS512;
use Cose\Algorithm\Signature\RSA\RS256;
use Cose\Algorithm\Signature\RSA\RS384;
use Cose\Algorithm\Signature\RSA\RS512;

/**
 * This service provides some common services of the web-authn library which are configured by the global configuration
 */
class WebauthnProvider
{
    private PublicKeyCredentialSourceRepository $publicKeyCredentialSourceRepository;

    private PublicKeyCredentialLoader $publicKeyCredentialLoader;

    private AuthenticatorAssertionResponseValidator $assertionResponseValidator;
    private AuthenticatorAttestationResponseValidator $attestationResponseValidator;
    private PublicKeyCredentialRpEntity $rpEntity;

    private ?string $rpID;
    private string $rpName;
    private ?string $rpIcon;

    public function __construct(PublicKeyCredentialSourceRepository $publicKeyCredentialSourceRepository, ?string $rpID, string $rpName, ?string $rpIcon)
    {
        $this->publicKeyCredentialSourceRepository = $publicKeyCredentialSourceRepository;

        //Create the RP entity
        $this->rpID = $rpID;
        $this->rpName = $rpName;
        $this->rpIcon = $rpIcon;

        $this->rpEntity = new PublicKeyCredentialRpEntity(
            $this->rpName,
            $this->rpID,
            $this->rpIcon
        );

        //Create the public key credential loader
        $attestationSupportStatementManager = new AttestationStatementSupportManager();
        $this->addAttestationTypes($attestationSupportStatementManager);
        $attestationObjectLoader = new AttestationObjectLoader($attestationSupportStatementManager);

        $this->publicKeyCredentialLoader = new PublicKeyCredentialLoader($attestationObjectLoader);

        //Create the assertion response validator
        $tokenBindingHandler = new TokenBindingNotSupportedHandler();
        $extensionOutputCheckerHandler = new ExtensionOutputCheckerHandler();
        $coseAlgorithmManager = new Manager();
        $this->addAlgorithms($coseAlgorithmManager);

        $this->assertionResponseValidator = new AuthenticatorAssertionResponseValidator(
            $this->publicKeyCredentialSourceRepository,
            $tokenBindingHandler,
            $extensionOutputCheckerHandler,
            $coseAlgorithmManager,
        );

        //Create the attestation response validator

        $this->attestationResponseValidator = new AuthenticatorAttestationResponseValidator(
            $attestationSupportStatementManager,
            $this->publicKeyCredentialSourceRepository,
            $tokenBindingHandler,
            $extensionOutputCheckerHandler
        );
    }

    private function addAlgorithms(Manager $coseAlgorithmManager) {
        $coseAlgorithmManager->add(new ES256());
        $coseAlgorithmManager->add(new ES256K());
        $coseAlgorithmManager->add(new ES384());
        $coseAlgorithmManager->add(new ES512());

        $coseAlgorithmManager->add(new RS256());
        $coseAlgorithmManager->add(new RS384());
        $coseAlgorithmManager->add(new RS512());

        $coseAlgorithmManager->add(new PS256());
        $coseAlgorithmManager->add(new PS384());
        $coseAlgorithmManager->add(new PS512());

        $coseAlgorithmManager->add(new ED256());
        $coseAlgorithmManager->add(new ED512());
    }

    private function addAttestationTypes(AttestationStatementSupportManager $attestationStatementSupportManager) {
        //For now we just support the none attestations statement type as we do not request it
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