package io.github.adorsysgis.keycloakstatuslist.validation;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.fail;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.when;

import io.github.adorsysgis.keycloakstatuslist.StatusListProtocolMapper;
import io.github.adorsysgis.keycloakstatuslist.config.StatusListConfig;
import io.github.adorsysgis.keycloakstatuslist.helpers.MockKeycloakTest;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.function.Executable;

/**
 * Validation check for scan finding 1: malformed numeric realm attributes throw a raw {@link
 * NumberFormatException} from the {@link StatusListProtocolMapper} constructor (and from direct
 * config getter calls), which breaks credential issuance and credential-issuer metadata discovery
 * even when {@code status-list-mandatory=false}.
 *
 * <p>Every test asserts the FIXED behaviour, so each test FAILS while the issue is present and
 * passes once the fix is in. See {@code validation/README.md} for the expected contract and the
 * ticket this belongs to.
 */
class Finding01ConfigParsingCheck extends MockKeycloakTest {

    @Test
    void mapperConstructionMustSurviveMalformedIssuanceTimeout() {
        enableStatusList();
        lenient()
                .when(realm.getAttribute(StatusListConfig.STATUS_LIST_ISSUANCE_TIMEOUT))
                .thenReturn("10000ms"); // plausible admin typo

        assertDoesNotThrow(
                () -> new StatusListProtocolMapper(session),
                "A typo in status-list-issuance-timeout must not break mapper construction. The constructor "
                        + "documents that misconfiguration is reported on the issuance path honoring "
                        + "status-list-mandatory, but today it escapes as a raw NumberFormatException and "
                        + "fails issuance/metadata unconditionally.");
    }

    @Test
    void mapperConstructionMustSurviveMalformedCircuitBreakerThreshold() {
        enableStatusList();
        lenient()
                .when(realm.getAttribute(StatusListConfig.STATUS_LIST_CIRCUIT_BREAKER_FAILURE_THRESHOLD))
                .thenReturn("abc");

        assertDoesNotThrow(
                () -> new StatusListProtocolMapper(session),
                "A malformed status-list-circuit-breaker-failure-threshold must not break mapper "
                        + "construction; it reaches the constructor via CircuitBreaker.getInstance(config).");
    }

    @Test
    void numericAttributesMustNeverSurfaceRawNumberFormatException() {
        List<String> numericKeys = List.of(
                StatusListConfig.STATUS_LIST_ISSUANCE_TIMEOUT,
                StatusListConfig.STATUS_LIST_REGISTRATION_TIMEOUT,
                StatusListConfig.STATUS_LIST_REGISTRATION_RETRIES,
                StatusListConfig.STATUS_LIST_REGISTRATION_COOLDOWN,
                StatusListConfig.STATUS_LIST_CIRCUIT_BREAKER_FAILURE_THRESHOLD);
        for (String key : numericKeys) {
            when(realm.getAttribute(key)).thenReturn("10s");
        }

        StatusListConfig config = new StatusListConfig(realm);
        assertNoRawNumberFormat(StatusListConfig.STATUS_LIST_ISSUANCE_TIMEOUT, config::getIssuanceTimeout);
        assertNoRawNumberFormat(StatusListConfig.STATUS_LIST_REGISTRATION_TIMEOUT, config::getRegistrationTimeout);
        assertNoRawNumberFormat(StatusListConfig.STATUS_LIST_REGISTRATION_RETRIES, config::getRegistrationRetries);
        assertNoRawNumberFormat(StatusListConfig.STATUS_LIST_REGISTRATION_COOLDOWN, config::getRegistrationCooldownMs);
        assertNoRawNumberFormat(
                StatusListConfig.STATUS_LIST_CIRCUIT_BREAKER_FAILURE_THRESHOLD,
                config::getCircuitBreakerFailureThreshold);
    }

    private void enableStatusList() {
        lenient().when(realm.getAttribute(StatusListConfig.STATUS_LIST_ENABLED)).thenReturn("true");
        lenient()
                .when(realm.getAttribute(StatusListConfig.STATUS_LIST_SERVER_URL))
                .thenReturn("https://status.example.com");
    }

    /**
     * The fixed contract: a malformed value either falls back to the documented default (preferred,
     * matching how {@code status-list-max-entries} is handled in the same class) or throws a
     * descriptive error naming the property. A raw {@link NumberFormatException} is never acceptable
     * because nothing on the issuance, metadata, or registration path handles it.
     */
    private void assertNoRawNumberFormat(String property, Executable getterCall) {
        try {
            getterCall.execute();
        } catch (Throwable thrown) {
            if (thrown instanceof NumberFormatException) {
                fail(property
                        + " surfaced a raw NumberFormatException ("
                        + thrown.getMessage()
                        + "). Fall back to the documented default with a warning, as "
                        + "status-list-max-entries already does, or throw a descriptive error naming the property.");
            }
            // Any other exception (e.g. a descriptive IllegalArgumentException) is acceptable.
        }
    }
}
