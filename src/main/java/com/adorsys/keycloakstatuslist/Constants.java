package com.adorsys.keycloakstatuslist;

public interface Constants {
    String MAPPER_ID = "oid4vc-status-list-claim-mapper";
    String CONFIG_LIST_ID_PROPERTY = "status.list.list_id";

    String ID_CLAIM_KEY = "id";
    String STATUS_CLAIM_KEY = "status";
    String TOKEN_STATUS_VALID = "VALID";

    String BEARER_PREFIX = "Bearer ";
    String HTTP_ENDPOINT_PUBLISH_PATH = "/statuslists/publish";
    String HTTP_ENDPOINT_UPDATE_PATH = "/statuslists/update";
    String HTTP_ENDPOINT_RETRIEVE_PATH = "/statuslists/%s";
}