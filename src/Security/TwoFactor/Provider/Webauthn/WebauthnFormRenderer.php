<?php

namespace Jbtronics\TFAWebauthn\Security\TwoFactor\Provider\Webauthn;

use Jbtronics\TFAWebauthn\Model\TwoFactorInterface;
use Jbtronics\TFAWebauthn\Services\Helpers\WebAuthnRequestStorage;
use Jbtronics\TFAWebauthn\Services\WebauthnAuthenticator;
use Jbtronics\TFAWebauthn\Services\WebauthnProvider;
use Scheb\TwoFactorBundle\Security\TwoFactor\Provider\TwoFactorFormRendererInterface;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorageInterface;
use Symfony\Component\Serializer\Encoder\JsonEncode;
use Symfony\Component\Serializer\Normalizer\AbstractObjectNormalizer;
use Twig\Environment;

final class WebauthnFormRenderer implements TwoFactorFormRendererInterface
{
    public function __construct(
        private readonly TokenStorageInterface $tokenStorage,
        private readonly Environment $twig,
        private readonly WebauthnAuthenticator $authenticator,
        private readonly string $template,
        private readonly WebAuthnRequestStorage $requestStorage,
        private readonly WebauthnProvider $webauthnProvider
    )
    {
    }

    public function renderForm(Request $request, array $templateVars): Response
    {
        $token = $this->tokenStorage->getToken();

        if ($token === null) {
            throw new \RuntimeException('Token cannot be null! You have to be already logged in to use this form.');
        }

        $user = $token->getUser();
        if (!$user instanceof TwoFactorInterface) {
            throw new \RuntimeException('User has to be a TwoFactorInterface!');
        }

        $requestData = $this->authenticator->generateAuthenticationRequest($user);
        $this->requestStorage->setActiveAuthRequest($requestData);

        $serializer = $this->webauthnProvider->getWebauthnSerializer();

        $templateVars['webauthn_request_data'] = $serializer->serialize($requestData, 'json', [
            AbstractObjectNormalizer::SKIP_NULL_VALUES => true, // Highly recommended!
            JsonEncode::OPTIONS => JSON_THROW_ON_ERROR, // Optional
        ]);

        $content = $this->twig->render($this->template, $templateVars);

        return new Response($content);
    }
}