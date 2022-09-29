<?php

namespace jbtronics\TFAWebauthn\Security\TwoFactor\Provider\Webauthn;

use jbtronics\TFAWebauthn\Model\TwoFactorInterface;
use jbtronics\TFAWebauthn\Services\WebauthnAuthenticator;
use Scheb\TwoFactorBundle\Security\TwoFactor\Provider\TwoFactorFormRendererInterface;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorageInterface;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Twig\Environment;

final class WebauthnFormRenderer implements TwoFactorFormRendererInterface
{
    private TokenInterface $token;
    private Environment $twig;
    private WebauthnAuthenticatorInterface $authenticator;

    private string $template;

    public function __construct(TokenStorageInterface $tokenStorage, Environment $twig, WebauthnAuthenticator $authenticator, string $template)
    {
        $this->token = $tokenStorage->getToken();
        $this->twig = $twig;
        $this->authenticator = $authenticator;
    }

    public function renderForm(Request $request, array $templateVars): Response
    {
        if ($this->token === null) {
            throw new \RuntimeException('Token cannot be null! You have to be already logged in to use this form.');
        }

        $user = $this->token->getUser();
        if (!$user instanceof TwoFactorInterface) {
            throw new \RuntimeException('User has to be a TwoFactorInterface!');
        }

        $requestData = $this->authenticator->getGenerateRequest($user);

        $templateVars['webauthn_request_data'] = json_encode($requestData, JSON_THROW_ON_ERROR);

        $content = $this->twig->render($this->template, $templateVars);

        return new Response($content);
    }
}