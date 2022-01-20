package natsTest;

import io.nats.client.NKey;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;

public class NatsUser {
    private final NKey accountSigningNKey;
    private final String accountId;
    private String userName;
    private String jwt = null;
    private NKey userNKey;
    private String NATS_USER_CRED_FORMAT = "-----BEGIN NATS USER JWT-----\n" +
            "%s\n" +
            "------END NATS USER JWT------\n" +
            "\n" +
            "************************* IMPORTANT *************************\n" +
            "    NKEY Seed printed below can be used to sign and prove identity.\n" +
            "    NKEYs are sensitive and should be treated as secrets.\n" +
            "\n" +
            "-----BEGIN USER NKEY SEED-----\n" +
            "%s\n" +
            "------END USER NKEY SEED------\n" +
            "\n" +
            "*************************************************************\n";

    NatsUser(NatsAccount account) throws IOException, GeneralSecurityException {
        this(account.getSigningNKey(),account.getId());
    }
    NatsUser(NatsAccount account, String userName) throws IOException, GeneralSecurityException {
        this(account.getSigningNKey(),account.getId(), userName);
    }
    NatsUser(NKey accountSigningNKey, String accoundId, String userName) throws IOException, GeneralSecurityException {
        this(accountSigningNKey, accoundId);
        this.userName = userName;
    }
    NatsUser(NKey accountSigningNKey, String accoundId) throws IOException, GeneralSecurityException {
        userNKey =  NKey.createUser(new SecureRandom());
        userName = new String(userNKey.getPublicKey());
        this.accountSigningNKey = accountSigningNKey;
        this.accountId = accoundId;
    }
    public String getJWT() throws GeneralSecurityException, IOException {
        if (jwt == null) {
            jwt = NatsUserJwtUtils.issueUserJWT( accountSigningNKey, accountId, new String(userNKey.getPublicKey()), userName);
        }
        return jwt;
    }
    public String getSeed() throws GeneralSecurityException, IOException {
        return new String(userNKey.getSeed());
    }
    public String getCred() throws GeneralSecurityException, IOException {
        return String.format(NATS_USER_CRED_FORMAT, getJWT(), getSeed());
    }
}
