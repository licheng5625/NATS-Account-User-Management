package natsTest;
import io.nats.client.*;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.assertEquals;

import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.concurrent.CompletableFuture;

public class NatsCreateUserTest {

    @Test
    public    void issueUserJWTSuccessMinimal() throws Exception {
        NatsOperator.signingKey =  "SXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX";
        NatsOperator.signingId = "OAXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX";
        NatsOperator.userJwt = "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX.XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX.XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX";
        NatsOperator.userPrivateKey = "SXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX";

        NatsAccount account = new NatsAccount(  "ACOUNT_NAME" );
        account.pushToServer("nats://localhost:4222");
        System.out.println(account.getJWT());
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

}
