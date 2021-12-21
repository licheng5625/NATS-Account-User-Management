package natsTest;
import io.nats.client.*;
import org.json.JSONObject;


import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;

public class NatsAccount {
    private NatsOperator operator;
    private String accountName;
    private String jwt = null;
    private NKey accountNKey;
    private NKey signingNKey;
    private String accountId;


    public NatsAccount(String accountName) throws IOException, GeneralSecurityException {
       this();
       this.accountName = accountName;
    }

    public NatsAccount() throws IOException, GeneralSecurityException {
        this.setAccountNkey();
        this.accountName = new String(accountNKey.getPublicKey());
    }

    public NKey getSigningNKey(){
        return signingNKey;
    }
    public String getAccountId(){
        return accountId;
    }

    public String getJWT() throws GeneralSecurityException, IOException {
        if (jwt == null) {
            jwt = NatsAccountJwtUtils.issueAccountJWT(NatsOperator.signingKey, NatsOperator.signingId,
                    new String(signingNKey.getPublicKey()), accountId, accountName);
        }
        return jwt;
    }

    public void pushToServer(String serverURL) throws GeneralSecurityException, IOException, InterruptedException, ExecutionException {
        jwt = getJWT();
        Options options = new Options.Builder().
                server(serverURL).
                authHandler(Nats.staticCredentials(NatsOperator.userJwt.toCharArray(),NatsOperator.userPrivateKey.toCharArray())).
                build();
        Connection nc = Nats.connect(options);
        //Subscription sub = nc.subscribe("$SYS.REQ.CLAIMS.UPDATE");
        CompletableFuture<Message> msg = nc.request("$SYS.REQ.CLAIMS.UPDATE", jwt.getBytes());


        String responds = new String(msg.get().getData());
        JSONObject respondsJson = new JSONObject(responds);
        if (respondsJson.has("error")  )
        {
            throw new InterruptedException("Cannot create Nats Account " + responds);
        }
        nc.close();
    }
    public NatsUser createNatsUser() throws GeneralSecurityException, IOException, InterruptedException, ExecutionException {
        return new NatsUser(this);
    }
    private void setAccountNkey() throws IOException, GeneralSecurityException {
        this.accountNKey = NKey.createAccount(new SecureRandom());
        this.signingNKey = NKey.createAccount(new SecureRandom());
        this.accountId = new String(signingNKey.getPublicKey());
    }
}
