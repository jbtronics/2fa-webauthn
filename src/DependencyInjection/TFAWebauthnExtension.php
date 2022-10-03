<?php

namespace Jbtronics\TFAWebauthn\DependencyInjection;

use Symfony\Component\Config\FileLocator;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Extension\Extension;
use Symfony\Component\DependencyInjection\Extension\PrependExtensionInterface;
use Symfony\Component\DependencyInjection\Loader\YamlFileLoader;

class TFAWebauthnExtension extends Extension
{

    public function load(array $configs, ContainerBuilder $container)
    {

        $loader = new YamlFileLoader($container, new FileLocator(__DIR__.'/../Resources/config'));
        $loader->load('services.yaml');

        $configuration = new Configuration();
        $config = $this->processConfiguration($configuration, $configs);

        $container->setParameter('jbtronics_webauthn_tfa.rpID', $config['rpID']);
        $container->setParameter('jbtronics_webauthn_tfa.timeout', $config['timeout']);
        $container->setParameter('jbtronics_webauthn_tfa.template', $config['template']);
        $container->setParameter('jbtronics_webauthn_tfa.U2FAppID', $config['U2FAppID']);
    }

}