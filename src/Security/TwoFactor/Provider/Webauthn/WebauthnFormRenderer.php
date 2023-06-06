<?php

namespace Jbtronics\TFAWebauthn\Security\TwoFactor\Provider\Webauthn;

use Jbtronics\TFAWebauthn\Model\TwoFactorInterface;
use Jbtronics\TFAWebauthn\Services\Helpers\WebAuthnRequestStorage;
use Jbtronics\TFAWebauthn\Services\WebauthnAuthenticator;
use Scheb\TwoFactorBundle\Security\TwoFactor\Provider\TwoFactorFormRendererInterface;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorageInterface;
use Twig\Environment;

final class WebauthnFormRenderer implements TwoFactorFormRendererInterface
{
    private TokenStorageInterface $tokenStorage;
    private Environment $twig;
    private WebauthnAuthenticatorInterface $authenticator;
    private WebAuthnRequestStorage $requestStorage;

    private string $template;

    public function __construct(TokenStorageInterface $tokenStorage, Environment $twig, WebauthnAuthenticator $authenticator, string $template, WebAuthnRequestStorage $webAuthnRequestStorage)
    {
        $this->tokenStorage = $tokenStorage;
        $this->twig = $twig;
        $this->authenticator = $authenticator;

        $this->template = $template;
        $this->requestStorage = $webAuthnRequestStorage;
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

        $templateVars['webauthn_request_data'] = json_encode($requestData, JSON_THROW_ON_ERROR);

        $content = $this->twig->render($this->template, $templateVars);

        return new Response($content);
    }
}