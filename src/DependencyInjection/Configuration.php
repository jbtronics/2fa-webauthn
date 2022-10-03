<?php

namespace Jbtronics\TFAWebauthn\DependencyInjection;

use Symfony\Component\Config\Definition\Builder\TreeBuilder;
use Symfony\Component\Config\Definition\ConfigurationInterface;

class Configuration implements ConfigurationInterface
{

    public function getConfigTreeBuilder()
    {
        $treeBuilder = new TreeBuilder('tfa_webauthn');
        $rootNode = $treeBuilder->getRootNode();

        $rootNode
            ->children()
            ->scalarNode('enabled')->defaultValue(false)->end()
            ->integerNode('timeout')->defaultValue(60000)->end()
            ->scalarNode('rpID')->defaultNull()->end()
            ->scalarNode('rpName')->defaultValue('Webauthn Application')->end()
            ->scalarNode('rpIcon')->defaultNull()->end()
            ->scalarNode('template')->defaultValue('@TFAWebauthn/Authentication/form.html.twig')->end()
            ->scalarNode('U2FAppID')->defaultNull()->end()

            //->scalarNode('form_renderer')->defaultNull()->end()
            //->scalarNode('issuer')->defaultNull()->end()
            //->scalarNode('server_name')->defaultNull()->end()
            //->scalarNode('template')->defaultValue('@SchebTwoFactor/Authentication/form.html.twig')->end()
            //->integerNode('digits')->defaultValue(6)->min(1)->end()
            //->integerNode('window')->defaultValue(1)->min(0)->end()
            //->end()
            ->end()
            ->end();

        return $treeBuilder;
    }
}