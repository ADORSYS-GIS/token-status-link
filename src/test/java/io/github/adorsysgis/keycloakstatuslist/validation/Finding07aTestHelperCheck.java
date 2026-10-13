package io.github.adorsysgis.keycloakstatuslist.validation;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import io.github.adorsysgis.keycloakstatuslist.helpers.MockKeycloakTest;
import org.junit.jupiter.api.Test;

/**
 * Validation check for scan finding 7a: {@code MockKeycloakTest.setPrivateField()} walks the class
 * hierarchy with {@code getDeclaredField()} and, when the field does not exist, simply falls out of
 * the loop and returns — silently. A renamed or typo'd field in any test would then skip the
 * intended setup while the test keeps passing (or fails with a misleading symptom).
 *
 * <p>Fixed contract asserted here: the helper must fail fast when the field cannot be found, and
 * must keep working for existing fields. FAILS while the no-op behaviour exists.
 */
class Finding07aTestHelperCheck extends MockKeycloakTest {

    @Test
    void setPrivateFieldShouldStillSetExistingFields() {
        Target target = new Target();
        setPrivateField(target, "value", "updated");
        assertEquals("updated", target.value, "setPrivateField must keep working for existing fields");
    }

    @Test
    void setPrivateFieldShouldFailFastOnUnknownFieldName() {
        assertThrows(
                Throwable.class,
                () -> setPrivateField(new Target(), "definitelyNoSuchField", "value"),
                "MockKeycloakTest.setPrivateField must throw when the field does not exist. The current "
                        + "silent no-op hides broken test setup: a renamed field would silently skip "
                        + "stubbing instead of failing the test with a clear message.");
    }

    private static class Target {
        private String value = "initial";
    }
}
