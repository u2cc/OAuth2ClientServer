package com.bondtech.configuration;


import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.security.oauth2.client.endpoint.OAuth2ClientCredentialsGrantRequest;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.util.CollectionUtils;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;

import java.io.FileInputStream;
import java.security.KeyStore;
import java.security.interfaces.RSAPrivateKey;
import java.util.Collections;
import java.util.Date;
import java.util.Objects;

@Slf4j
final class Util {

    public static final HttpHeaders DEFAULT_TOKEN_REQUEST_HEADERS = getDefaultTokenRequestHeaders();

    static HttpHeaders getTokenRequestHeaders(ClientRegistration clientRegistration) {
        HttpHeaders httpHeaders = new HttpHeaders();
        httpHeaders.addAll(DEFAULT_TOKEN_REQUEST_HEADERS);
        return httpHeaders;
    }

    private static HttpHeaders getDefaultTokenRequestHeaders() {
        HttpHeaders httpHeaders = new HttpHeaders();
        httpHeaders.setAccept(Collections.singletonList(MediaType.APPLICATION_JSON));
        MediaType contentType = MediaType.valueOf("application/x-www-form-urlencoded;charset=UTF-8");
        httpHeaders.setContentType(contentType);
        return httpHeaders;
    }

    static MultiValueMap<String, String> buildFormParameters(OAuth2ClientCredentialsGrantRequest clientCredentialsGrantRequest, String keyStoreLocation, String keyStorePassword, String keyPassword, String keyName, String kid)  {
        ClientRegistration clientRegistration = clientCredentialsGrantRequest.getClientRegistration();
        MultiValueMap<String, String> formParameters = new LinkedMultiValueMap<>();
        formParameters.add("grant-type", clientCredentialsGrantRequest.getGrantType().getValue());
        if(!CollectionUtils.isEmpty(clientRegistration.getScopes())) {
            formParameters.add("scope", String.join(" ", clientRegistration.getScopes()));
        }
        formParameters.add("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer");
        try {
            formParameters.add("client_assertion", generateSignedJwt(clientRegistration.getClientId(), clientRegistration.getProviderDetails().getTokenUri(), keyStoreLocation, keyStorePassword, keyPassword, keyName, kid));
        } catch (Exception e) {
            log.error("buildFormParameters error", e);
        }
        log.info("formParameters: {}", formParameters);
        return formParameters;
    }

    static String generateSignedJwt(final String clientId, final String audience, String keyStoreLocation, String keyStorePassword, String keyPassword, String keyName, String kid){
        String clientAssertionSignedJwt = "";
        try{
            JWSSigner signer = new RSASSASigner(Objects.requireNonNull(getPrivateKey(keyStoreLocation, keyStorePassword, keyPassword, keyName)));

            JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                    .subject(clientId)
                    .issuer(clientId)
                    .audience(audience)
                    .expirationTime(new Date(new Date().getTime() + 1000 * 60 * 60))
                    .build();

            SignedJWT signedJWT = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(kid).build(), claimsSet);
            signedJWT.sign(signer);
            clientAssertionSignedJwt = signedJWT.serialize();
            log.info("clientAssertionSignedJwt: {}", clientAssertionSignedJwt);
        } catch (Exception e){
            log.error("generateSignedJwt error", e);
        }

        return clientAssertionSignedJwt;
    }

    static private RSAPrivateKey getPrivateKey(String keyStoreLocation, String keyStorePassword, String keyPassword, String keyName) {
        try (FileInputStream fileInputStream = new FileInputStream(keyStoreLocation)) {
            KeyStore keyStore = KeyStore.getInstance("JKS");
            keyStore.load(fileInputStream, keyStorePassword.toCharArray());
            return (RSAPrivateKey) keyStore.getKey(keyName, keyPassword.toCharArray());
        } catch (Exception e) {
            log.error("getPrivateKey error", e);
            return null;
        }
    }

}
