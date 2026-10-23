<?php

declare(strict_types=1);

namespace Jbtronics\TFAWebauthn\DependencyInjection;

use Symfony\Component\Config\Definition\Builder\TreeBuilder;
use Symfony\Component\Config\Definition\ConfigurationInterface;

class Configuration implements ConfigurationInterface
{
    public function getConfigTreeBuilder(): TreeBuilder
    {
        $treeBuilder = new TreeBuilder('tfa_webauthn');

        $treeBuilder->getRootNode()
            ->children()
                ->scalarNode('enabled')->defaultFalse()->end()
                ->integerNode('timeout')->defaultValue(60000)->end()
                ->scalarNode('rpID')->defaultNull()->end()
                ->scalarNode('rpName')->defaultValue('Webauthn Application')->end()
                ->scalarNode('rpIcon')->defaultNull()->end()
                ->scalarNode('template')->defaultValue('@TFAWebauthn/Authentication/form.html.twig')->end()
                ->scalarNode('U2FAppID')->defaultNull()->end()
            ->end();

        return $treeBuilder;
    }
}
