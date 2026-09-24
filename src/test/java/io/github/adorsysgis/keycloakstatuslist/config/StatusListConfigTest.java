package io.github.adorsysgis.keycloakstatuslist.config;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.when;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.keycloak.models.RealmModel;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
class StatusListConfigTest {

    @Mock
    private RealmModel realm;

    @Test
    void parseMaxCredentialsPerUser_blankMeansUnlimited() {
        assertEquals(0, StatusListConfig.parseMaxCredentialsPerUser(null));
        assertEquals(0, StatusListConfig.parseMaxCredentialsPerUser(""));
        assertEquals(0, StatusListConfig.parseMaxCredentialsPerUser("  "));
    }

    @Test
    void parseMaxCredentialsPerUser_acceptsNonNegativeIntegers() {
        assertEquals(0, StatusListConfig.parseMaxCredentialsPerUser("0"));
        assertEquals(3, StatusListConfig.parseMaxCredentialsPerUser(" 3 "));
    }

    @Test
    void parseMaxCredentialsPerUser_rejectsNonNumericValues() {
        IllegalArgumentException exception =
                assertThrows(IllegalArgumentException.class, () -> StatusListConfig.parseMaxCredentialsPerUser("abc"));

        assertTrue(exception.getMessage().contains("status-list-max-credentials-per-user"));
        assertTrue(exception.getMessage().contains("abc"));
    }

    @Test
    void parseMaxCredentialsPerUser_rejectsNegativeValues() {
        IllegalArgumentException exception =
                assertThrows(IllegalArgumentException.class, () -> StatusListConfig.parseMaxCredentialsPerUser("-1"));

        assertTrue(exception.getMessage().contains("non-negative"));
        assertTrue(exception.getMessage().contains("Remove the config or use 0 for no realm-wide limit"));
    }

    @Test
    void getMaxCredentialsPerUser_rejectsInvalidRealmAttribute() {
        when(realm.getAttribute(StatusListConfig.STATUS_LIST_MAX_CREDENTIALS_PER_USER))
                .thenReturn("nope");

        assertThrows(IllegalArgumentException.class, () -> new StatusListConfig(realm).getMaxCredentialsPerUser());
    }

    @Test
    void getMaxCredentialsPerUser_rejectsNegativeRealmAttribute() {
        when(realm.getAttribute(StatusListConfig.STATUS_LIST_MAX_CREDENTIALS_PER_USER))
                .thenReturn("-2");

        assertThrows(IllegalArgumentException.class, () -> new StatusListConfig(realm).getMaxCredentialsPerUser());
    }

    @Test
    void parseOverflowPolicy_defaultsToRejectWhenBlankOrUnknown() {
        assertEquals(StatusListConfig.DEFAULT_OVERFLOW_POLICY, StatusListConfig.parseOverflowPolicy(null));
        assertEquals(StatusListConfig.DEFAULT_OVERFLOW_POLICY, StatusListConfig.parseOverflowPolicy(""));
        assertEquals(StatusListConfig.DEFAULT_OVERFLOW_POLICY, StatusListConfig.parseOverflowPolicy("maybe"));
    }

    @Test
    void parseOverflowPolicy_acceptsRejectAndRevokeOldest() {
        assertEquals("REJECT", StatusListConfig.parseOverflowPolicy("reject"));
        assertEquals("REVOKE_OLDEST", StatusListConfig.parseOverflowPolicy(" revoke_oldest "));
    }

    @Test
    void getOverflowPolicy_readsRealmAttribute() {
        when(realm.getAttribute(StatusListConfig.STATUS_LIST_OVERFLOW_POLICY)).thenReturn("REVOKE_OLDEST");

        assertEquals("REVOKE_OLDEST", new StatusListConfig(realm).getOverflowPolicy());
    }
}
