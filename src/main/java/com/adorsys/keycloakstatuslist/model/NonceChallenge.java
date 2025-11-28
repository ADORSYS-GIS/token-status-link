package com.adorsys.keycloakstatuslist.model;

public class NonceChallenge {
    private String nonce;
    private String aud;
    private long expires_in;

    public NonceChallenge() {
    }

    public NonceChallenge(String nonce, String aud, long expires_in) {
        this.nonce = nonce;
        this.aud = aud;
        this.expires_in = expires_in;
    }

    public String getNonce() {
        return nonce;
    }

    public void setNonce(String nonce) {
        this.nonce = nonce;
    }

    public String getAud() {
        return aud;
    }

    public void setAud(String aud) {
        this.aud = aud;
    }

    public long getExpires_in() {
        return expires_in;
    }

    public void setExpires_in(long expires_in) {
        this.expires_in = expires_in;
    }
}