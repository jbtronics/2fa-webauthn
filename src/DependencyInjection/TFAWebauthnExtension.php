<?php

declare(strict_types=1);

namespace Jbtronics\TFAWebauthn\DependencyInjection;

use Symfony\Component\Config\FileLocator;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Extension\Extension;
use Symfony\Component\DependencyInjection\Loader\PhpFileLoader;

class TFAWebauthnExtension extends Extension
{
    /**
     * @param array<array<string, mixed>> $configs
     */
    public function load(array $configs, ContainerBuilder $container): void
    {
        $loader = new PhpFileLoader($container, new FileLocator(__DIR__.'/../../config'));
        $loader->load('services.php');

        $config = $this->processConfiguration(new Configuration(), $configs);

        $container->setParameter('jbtronics_webauthn_tfa.timeout', $config['timeout']);
        $container->setParameter('jbtronics_webauthn_tfa.template', $config['template']);
        $container->setParameter('jbtronics_webauthn_tfa.U2FAppID', $config['U2FAppID']);

        $container->setParameter('jbtronics_webauthn_tfa.rpID', $config['rpID']);
        $container->setParameter('jbtronics_webauthn_tfa.rpName', $config['rpName']);
        $container->setParameter('jbtronics_webauthn_tfa.rpIcon', $config['rpIcon']);
    }
}
