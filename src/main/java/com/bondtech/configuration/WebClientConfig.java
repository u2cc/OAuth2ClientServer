package com.bondtech.configuration;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.security.oauth2.client.OAuth2ClientProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.oauth2.client.*;
import org.springframework.security.oauth2.client.endpoint.RestClientClientCredentialsTokenResponseClient;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.reactive.function.client.ServletOAuth2AuthorizedClientExchangeFilterFunction;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.reactive.function.client.ExchangeFilterFunction;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;

import java.util.List;
import java.util.stream.Collectors;

@EnableWebSecurity
@Configuration
@Slf4j
public class WebClientConfig {

    @Value("${jwt.keystore.location}")
    private String keystoreLocation;

    @Value("${jwt.keystore.password}")
    private String keystorePassword;

    @Value("${jwt.keystore.alias}")
    private String keyAlias;

    @Value("${jwt.keystore.kid}")
    private String kid;

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests(authorize -> authorize.requestMatchers("/to_get_strings").permitAll().anyRequest().authenticated());
        return http.build();
    }

    @Bean
    public OAuth2AuthorizedClientManager auth2AuthorizedClientManager(ClientRegistrationRepository clientRegistrationRepository,
                                                                      OAuth2AuthorizedClientService auth2AuthorizedClientService) {
        RestClientClientCredentialsTokenResponseClient restClientClientCredentialsTokenResponseClient = getRestClientClientCredentialsTokenResponseClient();
        OAuth2AuthorizedClientProvider oAuth2AuthorizedClientProvider = OAuth2AuthorizedClientProviderBuilder.builder()
                .clientCredentials(clientCredentialsGrantBuilder -> clientCredentialsGrantBuilder.accessTokenResponseClient(restClientClientCredentialsTokenResponseClient))
                .build();

        AuthorizedClientServiceOAuth2AuthorizedClientManager authorizedClientManager = new AuthorizedClientServiceOAuth2AuthorizedClientManager(clientRegistrationRepository, auth2AuthorizedClientService);
        authorizedClientManager.setAuthorizedClientProvider(oAuth2AuthorizedClientProvider);
        return authorizedClientManager;
    }

    private RestClientClientCredentialsTokenResponseClient getRestClientClientCredentialsTokenResponseClient() {
        RestClientClientCredentialsTokenResponseClient restClientClientCredentialsTokenResponseClient = new RestClientClientCredentialsTokenResponseClient();
        restClientClientCredentialsTokenResponseClient.setHeadersConverter(
                clientCredentialAssertionRequest -> Util.getTokenRequestHeaders(clientCredentialAssertionRequest.getClientRegistration())
        );
        restClientClientCredentialsTokenResponseClient.setParametersConverter(clientCredentialAssertionRequest -> Util.buildFormParameters(clientCredentialAssertionRequest, keystoreLocation, keystorePassword, keystorePassword, keyAlias, kid));

        return restClientClientCredentialsTokenResponseClient;
    }

    @Bean
    public ClientRegistrationRepository clientRegistrationRepository(OAuth2ClientProperties oAuth2ClientProperties) {
        Object String;
        List<ClientRegistration> clientRegistrations = oAuth2ClientProperties.getRegistration().entrySet().stream().map(entry -> {
            String clientRegistrationId = entry.getKey();
            OAuth2ClientProperties.Registration registration = entry.getValue();
            OAuth2ClientProperties.Provider provider = oAuth2ClientProperties.getProvider().get(registration.getProvider());
            return ClientRegistration.withRegistrationId(clientRegistrationId)
                    .clientId(registration.getClientId())
                    .clientAuthenticationMethod(ClientAuthenticationMethod.NONE)
                    .authorizationGrantType(new AuthorizationGrantType(registration.getAuthorizationGrantType()))
                    .redirectUri(registration.getRedirectUri())
                    .scope(registration.getScope())
                    .authorizationUri(provider.getAuthorizationUri())
                    .tokenUri(provider.getTokenUri())
                    .build();

                }

                ).collect(Collectors.toList());

        return new InMemoryClientRegistrationRepository(clientRegistrations);
    }

    @Bean
    public OAuth2AuthorizedClientService authorizedClientService(ClientRegistrationRepository clientRegistrationRepository) {
        return new InMemoryOAuth2AuthorizedClientService(clientRegistrationRepository);
    }

    @Bean
    WebClient webClient(OAuth2AuthorizedClientManager authorizedClientManager) {
        ServletOAuth2AuthorizedClientExchangeFilterFunction oauth2Client = new ServletOAuth2AuthorizedClientExchangeFilterFunction(authorizedClientManager);
        return WebClient.builder().apply(oauth2Client.oauth2Configuration()).filters(exchangeFilterFunctions -> exchangeFilterFunctions.add(ExchangeFilterFunction.ofRequestProcessor(clientRequest -> {
            log.info("Request: {} {}", clientRequest.method(), clientRequest.url());
            clientRequest.headers().forEach((name, values) -> values.forEach(value -> log.info("{}={}", name, value)));
            return Mono.just(clientRequest);
        }))).build();
    }

}
