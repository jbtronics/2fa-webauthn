<?php

declare(strict_types=1);

namespace Jbtronics\TFAWebauthn\DependencyInjection;

use Symfony\Component\Config\Definition\Builder\TreeBuilder;
use Symfony\Component\Config\Definition\ConfigurationInterface;

final class Configuration implements ConfigurationInterface
{
    public function getConfigTreeBuilder(): TreeBuilder
    {
        $treeBuilder = new TreeBuilder('tfa_webauthn');

        $treeBuilder->getRootNode()
            ->children()
                ->booleanNode('enabled')->defaultFalse()->end()
                ->integerNode('timeout')->defaultValue(60000)->min(1)->end()
                ->scalarNode('rpID')->defaultNull()->end()
                ->scalarNode('rpName')
                    ->info('Only used when rpID is not set. Otherwise browsers show the rpID, as the RP name is deprecated by the WebAuthn library.')
                    ->defaultValue('Webauthn Application')
                ->end()
                ->scalarNode('rpIcon')
                    ->setDeprecated('jbtronics/2fa-webauthn', '4.0', 'The "%node%" option is deprecated and has no effect, browsers do not display the relying party icon anymore.')
                    ->defaultNull()
                ->end()
                ->scalarNode('template')->defaultValue('@TFAWebauthn/Authentication/form.html.twig')->end()
                ->scalarNode('U2FAppID')->defaultNull()->end()
            ->end();

        return $treeBuilder;
    }
}
