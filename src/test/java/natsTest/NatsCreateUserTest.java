package natsTest;

import io.nats.client.*;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.time.Duration;

public class NatsCreateUserTest {

    @Test
    public    void issueUserJWTSuccessMinimal() throws Exception {
        NatsOperator.signingKey =  "SXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX";
        NatsOperator.signingId = "OXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX";
        NatsOperator.userJwt = "XXXXXXXXXXXX.XXXXXXXXXXXX.XXXXXXXXXXXX";
        NatsOperator.userPrivateKey = "SXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX";
        String importedAccountId = "AXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX";

        NatsAccount account = new NatsAccount(  "ACOUNT_NAME" );
        account.addImportRule(new NatsImportRule(importedAccountId, "*.dts.>", null,"receiving"));
        account.addImportRule(new NatsImportRule(importedAccountId,"*.dts.>", "API.PREFIX.dts.*","sending", NatsImportRule.Types.SERVICE));
        System.out.println(account.getJWT());

        account.pushToServer("nats://localhost:4222");
        NatsUser user = account.createNatsUser();
        System.out.println(user.getCred());

        Options options = new Options.Builder().
                server("nats://localhost:4222").
                authHandler(Nats.staticCredentials(user.getJWT().toCharArray(),user.getSeed().toCharArray())).
                build();
        Connection nc = Nats.connect(options);
        Subscription sub = nc.subscribe("updates");
        nc.publish("updates", "All is Well".getBytes(StandardCharsets.UTF_8));

        // Read a message
        Message msg = sub.nextMessage(1000);
        nc.flush(Duration.ZERO);
        String str = new String(msg.getData(), StandardCharsets.UTF_8);
        System.out.println(str);

    }

    @Test
    public void deleteAccount() throws Exception {
        NatsOperator.signingKey =  "SXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX";
        NatsOperator.signingId = "OXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX";
        NatsOperator.userJwt = "XXXXXXXXXXXX.XXXXXXXXXXXX.XXXXXXXXXXXX";
        NatsOperator.userPrivateKey = "SXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX";
        String importedAccountId = "AXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX";
        String[] deletingAccountIds =  new String[] { importedAccountId };

        String Jwt = NatsGenericJwtUtils.issueGenernicJWTforDeletingAccount(NatsOperator.signingKey,NatsOperator.signingId,deletingAccountIds );
        NatsAccount account = new NatsAccount(  "ACOUNT_NAME" );
        account.jwt = Jwt;
        System.out.println(Jwt);
        account.deleteFromServer("nats://localhost:4222");

     }
}
