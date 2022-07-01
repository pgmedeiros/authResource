package com.springsecurityteste.basico.security;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import com.springsecurityteste.basico.config.FalhaAuthCustom;
import com.springsecurityteste.basico.user.model.Users;
import com.springsecurityteste.basico.user.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.core.io.ClassPathResource;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.ClientSettings;
import org.springframework.security.oauth2.server.authorization.config.ProviderSettings;
import org.springframework.security.oauth2.server.authorization.config.TokenSettings;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;

import java.io.InputStream;
import java.security.KeyStore;
import java.time.Duration;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

@Configuration
@EnableWebSecurity
public class AuthSecurityConfig {

    @Autowired
    private AuthProperties authProperties;

    @Bean
    @Order(Ordered.HIGHEST_PRECEDENCE)
    public SecurityFilterChain defaultFilterChain(HttpSecurity httpSecurity) throws Exception {
        OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(httpSecurity);
        return httpSecurity.formLogin()
                .failureHandler(authenticationFailureHandler())
                .and()
        .build();
    }

    @Bean
    public SecurityFilterChain authFilterChain(HttpSecurity httpSecurity) throws Exception {
        httpSecurity.authorizeRequests().anyRequest().authenticated();
        return httpSecurity.formLogin()
                .failureHandler(authenticationFailureHandler())
                .and()
                .build();
    }

    @Bean
    public OAuth2TokenCustomizer<JwtEncodingContext> jwtEncodingContextOAuth2TokenCustomizer(UserRepository userRepository){
        return (context -> {
            Authentication authentication = context.getPrincipal();
            if (authentication.getPrincipal() instanceof User) {
                final User user = (User) authentication.getPrincipal();

                final Users userEntity = userRepository.findByUsername(user.getUsername())
                        .orElseThrow(() -> new RuntimeException("Não funcinoou"));

                Set<String> authorities = new HashSet<>();
                for (GrantedAuthority authority : user.getAuthorities()) {
                    authorities.add(authority.toString());
                }
                context.getClaims().claim("user_id", userEntity.getId().toString());
                context.getClaims().claim("user_username", userEntity.getUsername());
                context.getClaims().claim("authorities", authorities);
            }

        });
    }

    @Bean
    public RegisteredClientRepository registeredClientRepository(PasswordEncoder passwordEncoder) {
        RegisteredClient cinefilosFront = RegisteredClient
                .withId("1")
                .clientId("cinefilos")
                .clientSecret(passwordEncoder.encode("123456"))
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .redirectUri("http://localhost:3000/authorized")
                .redirectUri("https://oidcdebugger.com/debug")
                .redirectUri("https://oauth.pstmn.io/v1/callback")
                .scope("myuser:read")
                .scope("myuser:write")
                .tokenSettings(TokenSettings.builder()
                        .accessTokenTimeToLive(Duration.ofMinutes(15))
                        .refreshTokenTimeToLive(Duration.ofDays(1))
                        .reuseRefreshTokens(false)
                        .build())
                .clientSettings(ClientSettings.builder()
                        .requireAuthorizationConsent(true)
                        .build())
                .build();

        RegisteredClient resourceClient = RegisteredClient
                .withId("2")
                .clientId("awuser")
                .clientSecret(passwordEncoder.encode("123456"))
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                .scope("users:read")
                .scope("users:write")
                .tokenSettings(TokenSettings.builder()
                        .accessTokenTimeToLive(Duration.ofMinutes(5))
                        .build())
                .clientSettings(ClientSettings.builder()
                        .requireAuthorizationConsent(false)
                        .build())
                .build();

        return new InMemoryRegisteredClientRepository(
                Arrays.asList(cinefilosFront, resourceClient)
        );
    }

    @Bean
    public ProviderSettings providerSettings() {
        return ProviderSettings.builder()
                .issuer("http://localhost:8080")
                .build();
    }

    @Bean
    public JWKSet jwkSet() throws Exception {
        final var jskProperties = authProperties.getJks();
        final String path = jskProperties.getPath();
        final InputStream inputStream = new ClassPathResource(path)
                .getInputStream();
        final KeyStore keyStore = KeyStore.getInstance("JKS");

        keyStore.load(inputStream,
                jskProperties.getStorepass().toCharArray());

        RSAKey rsaKey = RSAKey.load(keyStore,
                jskProperties.getAlias(),
                jskProperties.getKeypass().toCharArray());

        return new JWKSet(rsaKey);
    }

    @Bean
    public JWKSource<SecurityContext> jwkSource(JWKSet jwkSet) {
        return (((jwkSelector, securityContext) -> jwkSelector.select(jwkSet)));
    }

    @Bean
    public JwtEncoder jwtEncoder(JWKSource<SecurityContext> jwkSource) {
        return new NimbusJwtEncoder(jwkSource);
    }

    @Bean
    public AuthenticationFailureHandler authenticationFailureHandler() {
        return new FalhaAuthCustom();
    }
}
