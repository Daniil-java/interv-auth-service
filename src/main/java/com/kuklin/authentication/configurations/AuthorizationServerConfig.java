package com.kuklin.authentication.configurations;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.CommandLineRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.server.authorization.client.JdbcRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.web.SecurityFilterChain;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPublicKey;
import java.text.ParseException;
import java.util.UUID;

@Configuration
@EnableWebSecurity
public class AuthorizationServerConfig {
    @Value("${auth.client.id}") String clientId;
    @Value("${auth.client.secret}") String clientSecret;
    @Value("${auth.client.redirect-uri}") String redirectUri;
    private static final String KEY_ID = "auth_key";

    /**
     * Основная цепочка фильтров безопасности для эндпоинтов Authorization Server.
     * Здесь настраиваются:
     *  - эндпоинты авторизации /oauth2/authorize, /oauth2/token, /.well-known/*
     *  - поддержка OpenID Connect (OIDC)
     *  - поддержка JWT для resource server (если этот сервис защищает свои API)
     */
    @Bean
    public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http) throws Exception {
        // Создаём конфигуратор
        OAuth2AuthorizationServerConfigurer authorizationServerConfigurer =
                OAuth2AuthorizationServerConfigurer.authorizationServer();

        // Включаем OIDC (ID Token, /.well-known/openid-configuration) /.well-known/openid-configuration — это
        // специальный URL, где
        // Authorization Server публикует метаданные о себе в формате JSON

        //Эти данные нужны клиентам (фронту, мобильным приложениям, библиотекам),
        // чтобы они могли автоматически настроиться на работу с сервером
        // без ручного прописывания всех URL и параметров.
        authorizationServerConfigurer.oidc(Customizer.withDefaults());

        http
                // Привязываем конфигуратор к HttpSecurity
                .securityMatcher(authorizationServerConfigurer.getEndpointsMatcher())
                .with(authorizationServerConfigurer, Customizer.withDefaults())
                // Включаем поддержку JWT для resource server
                .oauth2ResourceServer(oauth2 -> oauth2.jwt(Customizer.withDefaults()));

        return http.build();
    }

    /**
     * Репозиторий клиентов (приложений), которые могут получать токены.
     * Здесь используется JDBC-реализация, которая хранит данные в таблице oauth2_registered_client.
     */
    @Bean
    public RegisteredClientRepository registeredClientRepository(JdbcTemplate jdbcTemplate) {
        return new JdbcRegisteredClientRepository(jdbcTemplate);
    }

    /**
     * Источник JWK (JSON Web Key) для Spring Authorization Server.
     * Читает ключи из таблицы oauth_jwk по id = 'auth-key'.
     * Эти ключи используются для подписи JWT и публикации публичного ключа в /.well-known/jwks.json.
     */
    @Bean
    public JWKSource<SecurityContext> jwkSource(JdbcTemplate jdbcTemplate) throws NoSuchAlgorithmException, ParseException {

        // Проверяем, есть ли ключ с id = "auth-key"
        // Это стандартная таблица SAS, которую ожидает JDBC‑реализация Spring Authorization Server,
        // при использовании БД
        Integer count = jdbcTemplate.queryForObject(
                "SELECT COUNT(*) FROM oauth_jwk WHERE id = ?", Integer.class, KEY_ID
        );

        // Если нет — генерируем новый RSA-ключ и сохраняем
        if (count == 0) {
            KeyPair kp = KeyPairGenerator.getInstance("RSA").generateKeyPair();
            RSAKey rsaKey = new RSAKey.Builder((RSAPublicKey) kp.getPublic())
                    .privateKey(kp.getPrivate())
                    .keyID(KEY_ID) // фиксированный ID ключа
                    .build();
            String jwkJson = new JWKSet(rsaKey).toString();
            jdbcTemplate.update("INSERT INTO oauth_jwk (id, jwk) VALUES (?, ?)", KEY_ID, jwkJson);
        }

        // Читаем ключ из БД и парсим в JWKSet
        String jwkJson = jdbcTemplate.queryForObject(
                "SELECT jwk FROM oauth_jwk WHERE id = ?", String.class, KEY_ID
        );
        JWKSet jwkSet = JWKSet.parse(jwkJson);
        // Возвращаем источник ключей для SAS
        return (selector, context) -> selector.select(jwkSet);

    }

    /**
     * Инициализация ключей при первом старте.
     * Дублирует логику генерации ключа, чтобы гарантировать наличие записи в oauth_jwk.
     * Если в таблице oauth_jwk нет записи с id = 'auth-key', генерируется новый RSA-ключ,
     * сериализуется в JSON и сохраняется в базу.
     * Это нужно, чтобы при пустой БД сервис мог сам создать ключи для подписи токенов.
     */
    @Bean
    public CommandLineRunner initKeys(JdbcTemplate jdbcTemplate) {
        return args -> {
            Integer count = jdbcTemplate.queryForObject("SELECT COUNT(*) FROM oauth_jwk WHERE id = ?", Integer.class, KEY_ID);
            if (count == 0) {
                KeyPair kp = KeyPairGenerator.getInstance("RSA").generateKeyPair();
                RSAKey rsaKey = new RSAKey.Builder((java.security.interfaces.RSAPublicKey) kp.getPublic())
                        .privateKey(kp.getPrivate())
                        .keyID(KEY_ID)
                        .build();
                String jwkJson = new JWKSet(rsaKey).toString();
                jdbcTemplate.update("INSERT INTO oauth_jwk (id, jwk) VALUES (?, ?)", KEY_ID, jwkJson);
            }
        };
    }

    /**
     * Регистрирует клиента при старте приложения, если его ещё нет в БД.
     *  - client_id = "frontend-client" (магическое значение — идентификатор клиента)
     *  - client_secret = "secret" (захэширован)
     *  - grant types: authorization_code, refresh_token
     *  - redirectUri — URL фронта, куда SAS вернёт пользователя после логина
     *  - scopes: openid, profile, api.read
     *  - requireAuthorizationConsent(true) — показывать страницу согласия
     *  - requireProofKey(true) — включить PKCE (обязательно для SPA)
     */
    @Bean
    CommandLineRunner registerClient(RegisteredClientRepository repo, PasswordEncoder encoder) {
        return args -> {
            if (repo.findByClientId(clientId) == null) {
                RegisteredClient client = RegisteredClient.withId(UUID.randomUUID().toString())
                        .clientId(clientId)
                        .clientSecret(encoder.encode(clientSecret))
                        .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                        .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                        .redirectUri(redirectUri) // временный endpoint в auth-service
                        .scope("openid")
                        .scope("profile")
                        .scope("api.read")
                        .clientSettings(ClientSettings.builder()
                                .requireAuthorizationConsent(true)
                                .requireProofKey(true) // PKCE
                                .build())
                        .build();
                repo.save(client);
            }
        };
    }
}

