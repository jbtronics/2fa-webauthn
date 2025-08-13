<?php

declare(strict_types=1);

use Symfony\Component\DependencyInjection\Loader\Configurator\ContainerConfigurator;
use function Symfony\Component\DependencyInjection\Loader\Configurator\service;
use function Symfony\Component\DependencyInjection\Loader\Configurator\param;

return static function (ContainerConfigurator $container): void {
    $services = $container->services();

    $services
        ->set('jbtronics_webauthn_tfa.two_factor_provider', Jbtronics\TFAWebauthn\Security\TwoFactor\Provider\Webauthn\TwoFactorProvider::class)
        ->tag('scheb_two_factor.provider', ['alias' => 'webauthn_two_factor_provider'])
        ->args([
            '$authenticator' => service('jbtronics_webauthn_tfa.webauthn_authenticator'),
            '$formRenderer' => service('jbtronics_webauthn_tfa.form_renderer'),
            '$requestStorage' => service('jbtronics_webauthn_tfa.webauthn_request_storage'),
        ]);

    $services
        ->set('jbtronics_webauthn_tfa.u2f_app_id_provider', Jbtronics\TFAWebauthn\Services\Helpers\U2FAppIDProvider::class)
        ->args([
            '$requestStack' => service('request_stack'),
            '$override' => param('jbtronics_webauthn_tfa.U2FAppID'),
        ]);

    $services
        ->set('jbtronics_webauthn_tfa.form_renderer', Jbtronics\TFAWebauthn\Security\TwoFactor\Provider\Webauthn\WebauthnFormRenderer::class)
        ->args([
            '$tokenStorage' => service('security.token_storage'),
            '$twig' => service('twig'),
            '$template' => param('jbtronics_webauthn_tfa.template'),
            '$requestStorage' => service('jbtronics_webauthn_tfa.webauthn_request_storage'),
            '$authenticator' => service('jbtronics_webauthn_tfa.webauthn_authenticator'),
            '$webauthnProvider' => service('jbtronics_webauthn_tfa.webauthn_provider'),
        ]);

    $services
        ->set('jbtronics_webauthn_tfa.psr_request_helper', Jbtronics\TFAWebauthn\Services\Helpers\PSRRequestHelper::class)
        ->args([
            '$requestStack' => service('request_stack'),
        ]);

    $services
        ->set('jbtronics_webauthn_tfa.webauthn_authenticator', Jbtronics\TFAWebauthn\Services\WebauthnAuthenticator::class)
        ->args([
            '$publicKeyCredentialSourceRepository' => service('jbtronics_webauthn_tfa.user_public_key_source_repo'),
            '$u2FAppIDProvider' => service('jbtronics_webauthn_tfa.u2f_app_id_provider'),
            '$webauthnProvider' => service('jbtronics_webauthn_tfa.webauthn_provider'),
            '$PSRRequestHelper' => service('jbtronics_webauthn_tfa.psr_request_helper'),
            '$rpID' => param('jbtronics_webauthn_tfa.rpID'),
            '$timeout' => param('jbtronics_webauthn_tfa.timeout'),
            '$logger' => service('logger'),
        ]);

    $services
        ->set('jbtronics_webauthn_tfa.registration_helper', Jbtronics\TFAWebauthn\Services\TFAWebauthnRegistrationHelper::class)
        ->args([
            '$PSRRequestHelper' => service('jbtronics_webauthn_tfa.psr_request_helper'),
            '$timeout' => param('jbtronics_webauthn_tfa.timeout'),
            '$webauthnProvider' => service('jbtronics_webauthn_tfa.webauthn_provider'),
            '$security' => service('security.helper'),
            '$requestStorage' => service('jbtronics_webauthn_tfa.webauthn_request_storage'),
            '$keyCredentialSourceRepository' => service('jbtronics_webauthn_tfa.user_public_key_source_repo'),
        ]);

    $services
        ->set('jbtronics_webauthn_tfa.webauthn_request_storage', Jbtronics\TFAWebauthn\Services\Helpers\WebAuthnRequestStorage::class)
        ->args([
            '$requestStack' => service('request_stack'),
            '$webauthnProvider' => service('jbtronics_webauthn_tfa.webauthn_provider'),
        ]);

    $services
        ->set('jbtronics_webauthn_tfa.user_public_key_source_repo', Jbtronics\TFAWebauthn\Services\UserPublicKeyCredentialSourceRepository::class)
        ->args([
            '$security' => service('security.helper'),
        ]);

    $services
        ->set('jbtronics_webauthn_tfa.webauthn_provider', Jbtronics\TFAWebauthn\Services\WebauthnProvider::class)
        ->args([
            '$rpID' => param('jbtronics_webauthn_tfa.rpID'),
            '$rpName' => param('jbtronics_webauthn_tfa.rpName'),
            '$rpIcon' => param('jbtronics_webauthn_tfa.rpIcon'),
        ]);

    $services
        ->alias(Jbtronics\TFAWebauthn\Services\TFAWebauthnRegistrationHelper::class, 'jbtronics_webauthn_tfa.registration_helper');

};
