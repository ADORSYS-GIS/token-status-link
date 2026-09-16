package io.github.adorsysgis.keycloakstatuslist.service;

import io.github.adorsysgis.keycloakstatuslist.jpa.repository.StatusListRepository;
import org.jboss.logging.Logger;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.utils.KeycloakModelUtils;
import org.keycloak.utils.StringUtil;

/**
 * Removes the Keycloak issued-credential row created at token time when this mapper later rejects
 * issuance. The delete runs in its own transaction so a rollback of the current issuance request
 * cannot restore the row. Keycloak's issued-credential model has no failed status, so the row is
 * deleted rather than marked failed: listing omits it, and revocation returns not found.
 */
public class RejectedIssuanceCleanup {

    private static final Logger logger = Logger.getLogger(RejectedIssuanceCleanup.class);

    private final KeycloakSession session;
    private final StatusListRepository statusListRepository;

    public RejectedIssuanceCleanup(KeycloakSession session, StatusListRepository statusListRepository) {
        this.session = session;
        this.statusListRepository = statusListRepository;
    }

    /**
     * Deletes the orphan issued credential and marks any {@code INIT} reservation for it as
     * {@code FAILURE}. Failures are logged and swallowed so the original reject still reaches the client.
     */
    public void discard(String realmId, String issuedCredentialId) {
        if (StringUtil.isBlank(issuedCredentialId)) {
            logger.warn("Mapper rejected issuance but no issued credential id was available to delete");
            return;
        }

        deleteIssuedCredential(issuedCredentialId);
        releaseInitReservation(realmId, issuedCredentialId);
    }

    private void deleteIssuedCredential(String issuedCredentialId) {
        if (session == null || session.getKeycloakSessionFactory() == null) {
            logger.errorf(
                    "Cannot delete orphan issued credential %s: Keycloak session is not available", issuedCredentialId);
            return;
        }

        try {
            KeycloakModelUtils.runJobInTransaction(session.getKeycloakSessionFactory(), nested -> {
                boolean removed = nested.users().removeIssuedVerifiableCredential(issuedCredentialId);
                if (removed) {
                    logger.infof("Deleted orphan issued credential %s after mapper reject", issuedCredentialId);
                } else {
                    logger.warnf(
                            "Issued credential %s was not found to delete after mapper reject", issuedCredentialId);
                }
            });
        } catch (RuntimeException e) {
            logger.errorf(e, "Failed to delete orphan issued credential %s after mapper reject", issuedCredentialId);
        }
    }

    private void releaseInitReservation(String realmId, String issuedCredentialId) {
        if (statusListRepository == null || StringUtil.isBlank(realmId)) {
            return;
        }

        try {
            int released = statusListRepository.markInitMappingsFailed(realmId, issuedCredentialId);
            if (released > 0) {
                logger.infof(
                        "Marked %d INIT status-list reservation(s) failed for issued credential %s",
                        released, issuedCredentialId);
            }
        } catch (RuntimeException e) {
            logger.errorf(
                    e,
                    "Failed to mark INIT status-list reservation failed for issued credential %s",
                    issuedCredentialId);
        }
    }
}
