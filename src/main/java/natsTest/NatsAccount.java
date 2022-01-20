package natsTest;
import io.nats.client.*;
import org.json.JSONObject;


import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;

public class NatsAccount {
    private NatsOperator operator;
    private String accountName;
    public String jwt = null;
    private NKey accountNKey;
    private NKey signingNKey;
    private String accountId;
    private String accountSeed;
    private static final String SYS_REQ_CLAIM_UPDATE_SUBJECT = "$SYS.REQ.CLAIMS.UPDATE";
    private static final String SYS_REQ_CLAIM_DELETE = "$SYS.REQ.CLAIMS.DELETE";
    private ArrayList<NatsImportRule> importRules = new ArrayList<>();
    private static final String NATS_DTS_SUBJECT = ".dts.";
    private static final String NATS_SUBJECT_WILDCARD_SUFFIX = ">";


    public NatsAccount(String accountName) throws IOException, GeneralSecurityException {
       this();
       this.accountName = accountName;
    }

    public NatsAccount() throws IOException, GeneralSecurityException {
        this.setAccountNkey();
        this.accountName = new String(accountNKey.getPublicKey());
    }


    public NKey getSigningNKey() {
        return signingNKey;
    }

    public String getId() {
        return accountId;
    }

    public String getSeed() {
        return accountSeed;
    }

    public String getJWT() throws GeneralSecurityException, IOException {
        if (jwt == null) {
            if (importRules.isEmpty()) {
                jwt = NatsAccountJwtUtils.issueAccountJWT(NatsOperator.signingKey, NatsOperator.signingId,
                        new String(signingNKey.getPublicKey()), accountId, accountName);
            } else {
                jwt = NatsAccountJwtUtils.issueAccountJWT(NatsOperator.signingKey, NatsOperator.signingId,
                        new String(signingNKey.getPublicKey()), accountId, accountName, importRules);
            }
        }
        return jwt;
    }

    public void addImportRule(NatsImportRule rule) {
        importRules.add(rule);
    }

    public JSONObject sendMessageToServer(String serverURL, String subject, String payload) throws GeneralSecurityException, IOException, InterruptedException, ExecutionException {

        Options options = new Options.Builder().
                server(serverURL).
                authHandler(Nats.staticCredentials(NatsOperator.userJwt.toCharArray(),NatsOperator.userPrivateKey.toCharArray())).
                build();

        Connection nc = Nats.connect(options);
        CompletableFuture<Message> msg = nc.request(subject, payload.getBytes(StandardCharsets.UTF_8));
        String responds = new String(msg.get().getData(), StandardCharsets.UTF_8);
        nc.close();
        return new JSONObject(responds);
    }

    public void pushToServer(String serverURL) throws GeneralSecurityException, IOException, InterruptedException, ExecutionException {
        jwt = getJWT();
        JSONObject respondsJson = sendMessageToServer(serverURL, SYS_REQ_CLAIM_UPDATE_SUBJECT, jwt);
        if (respondsJson.has("error")) {
            throw new InterruptedException("Cannot create Nats Account " + respondsJson);
        }
    }

    public void deleteFromServer(String serverURL) throws GeneralSecurityException, IOException, InterruptedException, ExecutionException {
        String jwtForDeletion = NatsGenericJwtUtils.issueGenernicJWTforDeletingAccount(NatsOperator.signingKey, NatsOperator.signingId, new String[]{this.accountId});
        JSONObject respondsJson = sendMessageToServer(serverURL, SYS_REQ_CLAIM_DELETE, jwtForDeletion);
        if (respondsJson.has("error")) {
            throw new InterruptedException("Cannot Delete Nats Account " + respondsJson);
        }
    }

    public NatsUser createNatsUser() throws GeneralSecurityException, IOException {
        return new NatsUser(this);
    }

    private void setAccountNkey() throws IOException, GeneralSecurityException {
        this.accountNKey = NKey.createAccount(new SecureRandom());
        this.signingNKey = NKey.createAccount(new SecureRandom());
        this.accountId = new String(accountNKey.getPublicKey());
        this.accountSeed = new String(accountNKey.getSeed());
    }

    public static String getSubject(String serviceInstanceId) {
        return serviceInstanceId + NATS_DTS_SUBJECT + NATS_SUBJECT_WILDCARD_SUFFIX;
    }

}
