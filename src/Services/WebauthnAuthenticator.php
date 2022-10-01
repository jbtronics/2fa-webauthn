<?php

namespace Jbtronics\TFAWebauthn\Services;

use Jbtronics\TFAWebauthn\Model\TwoFactorInterface;
use Jbtronics\TFAWebauthn\Security\TwoFactor\Provider\Webauthn\WebauthnAuthenticatorInterface;
use Jbtronics\TFAWebauthn\Services\Helpers\KeyCollector;
use Jbtronics\TFAWebauthn\Services\Helpers\U2FAppIDProvider;
use Jbtronics\TFAWebauthn\Services\Helpers\WebauthnProvider;
use Jbtronics\TFAWebauthn\Services\Helpers\WebAuthnRequestStorage;
use lbuchs\WebAuthn\WebAuthn;
use lbuchs\WebAuthn\WebAuthnException;

class WebauthnAuthenticator implements WebauthnAuthenticatorInterface
{

    private WebAuthn $webauthn;
    private U2FAppIDProvider $u2fAppIDProvider;
    private KeyCollector $keyCollector;

    protected string $requireUserVerification = "discouraged";
    protected int $timeout = 20;


    public function __construct(WebauthnProvider $webauthnProvider, U2FAppIDProvider $u2FAppIDProvider, KeyCollector $keyCollector)
    {
        $this->webauthn = $webauthnProvider->getInstance();
        $this->u2fAppIDProvider = $u2FAppIDProvider;
        $this->keyCollector = $keyCollector;
    }

    public function getGenerateRequest(TwoFactorInterface $user): \stdClass
    {
        $credentialsID = $this->keyCollector->collectKeyIDs($user);

        $data = $this->webauthn->getGetArgs(
            $credentialsID,
            $this->timeout,
            true,
            true,
            true,
            true,
            $this->requireUserVerification
        );

        //Add appid extension for backward compatibility with U2F
        $extensions = new \stdClass();
        $extensions->appid = $this->u2fAppIDProvider->getAppID();
        $data->publicKey->extensions = $extensions;

        return $data;
    }

    public function checkRequest(TwoFactorInterface $user, \stdClass $request, \stdClass $response): bool
    {
        //We have to use rawId here, as we want the not U2F formatted keyId, as we format it in the KeyCollector for the legacy keys
        //U2F keys can be detected by the fact, that id and rawId differs
        $keyId = base64_decode($response->rawId);
        $publicKey = $this->keyCollector->findPublicKeyForID($user, $keyId);

        if ($publicKey === null) {
            //No public key found in the database for the returned handle
            return false;
        }

        try {
            return $this->webauthn->processGet(
                //Data we get from the response
                base64_decode($response->response->clientDataJSON),
                base64_decode($response->response->authenticatorData),
                base64_decode($response->response->signature),
                //Data we take from the request
                $publicKey,
                $request->publicKey->challenge,
            );
        } catch(WebAuthnException $exception) {
            return false;
        }
    }
}