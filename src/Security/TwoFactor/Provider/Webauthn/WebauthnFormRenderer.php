<?php

declare(strict_types=1);

namespace Jbtronics\TFAWebauthn\Security\TwoFactor\Provider\Webauthn;

use Jbtronics\TFAWebauthn\Model\TwoFactorInterface;
use Jbtronics\TFAWebauthn\Services\Helpers\WebAuthnRequestStorage;
use Jbtronics\TFAWebauthn\Services\WebauthnProvider;
use Scheb\TwoFactorBundle\Security\TwoFactor\Provider\TwoFactorFormRendererInterface;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorageInterface;
use Symfony\Component\Serializer\Encoder\JsonEncode;
use Symfony\Component\Serializer\Normalizer\AbstractObjectNormalizer;
use Twig\Environment;

final readonly class WebauthnFormRenderer implements TwoFactorFormRendererInterface
{
    public function __construct(
        private TokenStorageInterface $tokenStorage,
        private Environment $twig,
        private WebauthnAuthenticatorInterface $authenticator,
        private string $template,
        private WebAuthnRequestStorage $requestStorage,
        private WebauthnProvider $webauthnProvider,
    ) {
    }

    /**
     * @param array<string, mixed> $templateVars
     */
    public function renderForm(Request $request, array $templateVars): Response
    {
        $token = $this->tokenStorage->getToken();
        if (null === $token) {
            throw new \RuntimeException('Token cannot be null! You have to be already logged in to use this form.');
        }

        $user = $token->getUser();
        if (!$user instanceof TwoFactorInterface) {
            throw new \RuntimeException('User has to be a TwoFactorInterface!');
        }

        $requestData = $this->authenticator->generateAuthenticationRequest($user);
        $this->requestStorage->setActiveAuthRequest($requestData);

        $templateVars['webauthn_request_data'] = $this->webauthnProvider->getWebauthnSerializer()->serialize($requestData, 'json', [
            AbstractObjectNormalizer::SKIP_NULL_VALUES => true,
            JsonEncode::OPTIONS => \JSON_THROW_ON_ERROR,
        ]);

        return new Response($this->twig->render($this->template, $templateVars));
    }
}
