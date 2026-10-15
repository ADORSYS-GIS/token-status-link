package io.github.adorsysgis.keycloakstatuslist.validation;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.when;

import io.github.adorsysgis.keycloakstatuslist.config.StatusListConfig;
import nl.altindag.log.LogCaptor;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.keycloak.models.RealmModel;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

/**
 * Validation check for scan finding 4: leaving {@code status-list-max-entries} unset is the
 * documented default (10000), yet {@link StatusListConfig#getStatusListMaxEntries()} logs a WARN on
 * EVERY call — i.e. on every issued credential via the protocol mapper's {@code setClaim}.
 *
 * <p>Fixed contract asserted here: the unset-default path must not emit a WARN (use DEBUG/INFO);
 * WARN stays reserved for genuinely invalid values. FAILS while the warning is logged per call.
 */
@ExtendWith(MockitoExtension.class)
class Finding04ConfigLoggingCheck {

    private final LogCaptor logCaptor = LogCaptor.forName("io.github.adorsysgis.keycloakstatuslist");

    @Mock
    private RealmModel realm;

    @Test
    void unsetMaxEntriesMustNotWarnOnEveryCall() {
        when(realm.getAttribute(StatusListConfig.STATUS_LIST_MAX_ENTRIES)).thenReturn(null);

        assertEquals(
                StatusListConfig.DEFAULT_MAX_ENTRIES,
                new StatusListConfig(realm).getStatusListMaxEntries(),
                "unset status-list-max-entries must still resolve to the documented default");

        assertTrue(
                logCaptor.getWarnLogs().stream()
                        .noneMatch(message -> message.contains("No max entries value configured")),
                "Leaving status-list-max-entries unset is the documented default and must not log a WARN "
                        + "on every issuance. Demote the default-path message to DEBUG; keep WARN for the "
                        + "invalid-value case. Captured WARN logs: "
                        + logCaptor.getWarnLogs());
    }
}
