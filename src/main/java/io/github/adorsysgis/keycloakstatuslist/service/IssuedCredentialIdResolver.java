package io.github.adorsysgis.keycloakstatuslist.service;

import static org.keycloak.OID4VCConstants.CREDENTIAL_CONFIGURATION_ID;
import static org.keycloak.OID4VCConstants.OPENID_CREDENTIAL;

import jakarta.ws.rs.core.HttpHeaders;
import java.util.Optional;
import java.util.stream.Stream;
import org.apache.hc.client5.http.auth.StandardAuthScheme;
import org.jboss.logging.Logger;
import org.keycloak.TokenVerifier;
import org.keycloak.common.VerificationException;
import org.keycloak.models.KeycloakSession;
import org.keycloak.protocol.oid4vc.model.OID4VCAuthorizationDetail;
import org.keycloak.representations.AccessToken;
import org.keycloak.representations.AuthorizationDetailsJSONRepresentation;
import org.keycloak.utils.StringUtil;

public class IssuedCredentialIdResolver {

    private static final Logger logger = Logger.getLogger(IssuedCredentialIdResolver.class);
    private static final String DPOP_AUTH_SCHEME = "dpop";

    private final KeycloakSession session;

    public IssuedCredentialIdResolver(KeycloakSession session) {
        this.session = session;
    }

    public Optional<String> resolve() {
        return openidCredentialDetails()
                .map(detail -> detail.getCustomData().get(OID4VCAuthorizationDetail.ISSUED_CREDENTIAL_ID))
                .filter(String.class::isInstance)
                .map(String.class::cast)
                .filter(StringUtil::isNotBlank)
                .findFirst();
    }

    public Optional<String> resolveCredentialConfigurationId() {
        return openidCredentialDetails()
                .map(this::readCredentialConfigurationId)
                .filter(StringUtil::isNotBlank)
                .findFirst();
    }

    private Optional<String> getAccessTokenFromAuthorizationHeader() {
        try {
            HttpHeaders headers = session.getContext().getRequestHeaders();
            if (headers == null) {
                return Optional.empty();
            }

            String authorizationHeader = headers.getHeaderString(HttpHeaders.AUTHORIZATION);
            if (StringUtil.isBlank(authorizationHeader)) {
                return Optional.empty();
            }

            String[] authParts = authorizationHeader.trim().split("\\s+", 2);
            if (authParts.length != 2 || !isAccessTokenAuthScheme(authParts[0])) {
                return Optional.empty();
            }

            String token = authParts[1].trim();
            return StringUtil.isBlank(token) ? Optional.empty() : Optional.of(token);
        } catch (RuntimeException e) {
            logger.debug("Could not read access token from current request", e);
            return Optional.empty();
        }
    }

    private boolean isAccessTokenAuthScheme(String scheme) {
        return StandardAuthScheme.BEARER.equalsIgnoreCase(scheme) || DPOP_AUTH_SCHEME.equalsIgnoreCase(scheme);
    }

    private Optional<AccessToken> readAccessToken(String token) {
        try {
            return Optional.of(TokenVerifier.create(token, AccessToken.class).getToken());
        } catch (VerificationException e) {
            logger.debug("Could not parse current access token as Keycloak access token", e);
            return Optional.empty();
        }
    }

    private Stream<AuthorizationDetailsJSONRepresentation> openidCredentialDetails() {
        return getAccessTokenFromAuthorizationHeader()
                .flatMap(this::readAccessToken)
                .map(AccessToken::getAuthorizationDetails)
                .stream()
                .flatMap(details -> details == null ? Stream.empty() : details.stream())
                .filter(detail -> OPENID_CREDENTIAL.equals(detail.getType()));
    }

    private String readCredentialConfigurationId(AuthorizationDetailsJSONRepresentation detail) {
        Object custom =
                detail.getCustomData() == null ? null : detail.getCustomData().get(CREDENTIAL_CONFIGURATION_ID);
        if (custom instanceof String value) {
            return value;
        }

        try {
            return detail.asSubtype(OID4VCAuthorizationDetail.class).getCredentialConfigurationId();
        } catch (RuntimeException e) {
            logger.debug("Could not read credential_configuration_id from authorization details", e);
            return null;
        }
    }
}
