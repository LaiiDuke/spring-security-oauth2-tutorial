package com.dailycodebuffer.oauthserver.config;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.config.annotation.web.configurers.oauth2.server.authorization.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.OAuth2TokenType;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenCustomizer;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.ClientSettings;
import org.springframework.security.oauth2.server.authorization.config.ProviderSettings;
import org.springframework.security.oauth2.server.authorization.web.OAuth2TokenEndpointFilter;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.util.matcher.RequestMatcher;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;

@Configuration(proxyBeanMethods = false)
public class AuthorizationServerConfiguration {

	private static final Logger LOGGER = LogManager.getLogger(AuthorizationServerConfiguration.class);

	@Autowired
	private PasswordEncoder passwordEncoder;

	@Bean
	@Order(Ordered.HIGHEST_PRECEDENCE)
	public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http) throws Exception {

		OAuth2AuthorizationServerConfigurer<HttpSecurity> authorizationServerConfigurer = new OAuth2AuthorizationServerConfigurer<>();

		LOGGER.debug("in authorizationServerSecurityFilterChain");

		authorizationServerConfigurer.authorizationEndpoint(authorizationEndpoint ->
			authorizationEndpoint.consentPage("/oauth2/consent"));

		RequestMatcher endpointsMatcher = authorizationServerConfigurer.getEndpointsMatcher();

		http
			.requestMatcher(endpointsMatcher)
			.authorizeRequests(authorizeRequests -> authorizeRequests.anyRequest().authenticated())
			.csrf(csrf -> csrf.ignoringRequestMatchers(endpointsMatcher))
			.apply(authorizationServerConfigurer);

		SecurityFilterChain securityFilterChain = http.formLogin(Customizer.withDefaults()).build();

		/**
		 * Custom configuration for Resource Owner Password grant type and custom oauth2 token. Current implementation has no
		 * support for Resource Owner Password grant type
		 */
		AuthenticationManager authenticationManager = http.getSharedObject(AuthenticationManager.class);
		JwtEncoder jwtEncoder = http.getSharedObject(JwtEncoder.class);
		ProviderSettings providerSettings = http.getSharedObject(ProviderSettings.class);
		OAuth2AuthorizationService authorizationService = http.getSharedObject(OAuth2AuthorizationService.class);
		OAuth2TokenCustomizer<JwtEncodingContext> jwtCustomizer = buildCustomizer();

		CustomOAuth2ResourceOwnerPasswordAuthenticationProvider resourceOwnerPasswordAuthenticationProvider =
				new CustomOAuth2ResourceOwnerPasswordAuthenticationProvider(authorizationService, jwtEncoder);
		if (jwtCustomizer != null) {
			resourceOwnerPasswordAuthenticationProvider.setJwtCustomizer(jwtCustomizer);
		}

		resourceOwnerPasswordAuthenticationProvider.setProviderSettings(providerSettings);

		CustomOAuth2TokenEndpointFilter customTokenEndpointFilter = new CustomOAuth2TokenEndpointFilter(authenticationManager, providerSettings.getTokenEndpoint());

		// This will add new authentication provider in the list of existing authentication providers.
		http.authenticationProvider(resourceOwnerPasswordAuthenticationProvider);
		http.addFilterBefore(customTokenEndpointFilter, OAuth2TokenEndpointFilter.class);

		securityFilterChain = http.getOrBuild();

		securityFilterChain.getFilters().add(19, customTokenEndpointFilter);

		return securityFilterChain;
	}


	@Bean
	public JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource) {
		return OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource);
	}


	@Bean
    public OAuth2TokenCustomizer<JwtEncodingContext> buildCustomizer() {
        OAuth2TokenCustomizer<JwtEncodingContext> customizer = (context) -> {

        	AbstractAuthenticationToken token = null;

        	Authentication authenticataion = SecurityContextHolder.getContext().getAuthentication();
        	if (authenticataion instanceof UsernamePasswordAuthenticationToken ) {
        		token = (UsernamePasswordAuthenticationToken) authenticataion;
        	}

        	if (authenticataion instanceof OAuth2ClientAuthenticationToken ) {
        		token = (OAuth2ClientAuthenticationToken) authenticataion;
        	}

        	if (token != null) {
        		if (token.isAuthenticated() && OAuth2TokenType.ACCESS_TOKEN.equals(context.getTokenType())) {

        			boolean containsUserPrincipal = context.hasKey("user_principal");
        			if (containsUserPrincipal) {
        				User user = context.get("user_principal");
        				if (user != null) {
        					Set<String> authorities = user.getAuthorities().stream()
        							.map(GrantedAuthority::getAuthority)
        							.collect(Collectors.toSet());

                			context.getClaims().claim(OAuth2ParameterNames.SCOPE, authorities);
        				}
        			} else {
        				Authentication principal = context.getPrincipal();
            			Set<String> authorities = principal.getAuthorities().stream()
    							.map(GrantedAuthority::getAuthority)
    							.collect(Collectors.toSet());

            			context.getClaims().claim(OAuth2ParameterNames.SCOPE, authorities);
        			}

                   // context.getClaims().claim("user-authorities", token.getAuthorities()
                           // .stream()
                           // .map(GrantedAuthority::getAuthority)
                           // .collect(Collectors.toList()));
                }
        	}
        };

        return customizer;
    }


	@Bean
	public RegisteredClientRepository registeredClientRepository() {
		RegisteredClient registeredClient = RegisteredClient.withId(UUID.randomUUID().toString())
				.clientId("api-client")
				.clientSecret(passwordEncoder.encode("secret"))
				.clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
				.authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
				.authorizationGrantType(AuthorizationGrantType.PASSWORD)
				.authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
				.redirectUri("http://127.0.0.1:8080/login/oauth2/code/api-client-oidc")
				.redirectUri("http://127.0.0.1:8080/authorized")
				.scope(OidcScopes.OPENID)
				.scope("api.read")
				.clientSettings(ClientSettings.builder().requireAuthorizationConsent(true).build())
				.build();


		return new InMemoryRegisteredClientRepository(registeredClient);
	}

	@Bean
	UserDetailsService users() {
		UserDetails user = User.builder()
				.username("admin")
				.password(passwordEncoder.encode("password"))
				.authorities("admin")
				.build();
		return new InMemoryUserDetailsManager(user);
	}
	@Bean
	public JWKSource<SecurityContext> jwkSource() {
		RSAKey rsaKey = generateRsa();
		JWKSet jwkSet = new JWKSet(rsaKey);
		return (jwkSelector, securityContext) -> jwkSelector.select(jwkSet);
	}

	private static RSAKey generateRsa() {
		KeyPair keyPair = generateRsaKey();
		RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
		RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
		return new RSAKey.Builder(publicKey)
				.privateKey(privateKey)
				.keyID(UUID.randomUUID().toString())
				.build();
	}

	private static KeyPair generateRsaKey() {
		KeyPair keyPair;
		try {
			KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
			keyPairGenerator.initialize(2048);
			keyPair = keyPairGenerator.generateKeyPair();
		} catch (Exception ex) {
			throw new IllegalStateException(ex);
		}
		return keyPair;
	}

	@Bean
	public ProviderSettings providerSettings() {
		return ProviderSettings.builder()
				.issuer("http://localhost:9000")
				.build();
	}
}
