package natsTest;
import io.nats.client.NKey;
import org.json.JSONArray;
import org.json.JSONObject;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.util.Date;

import static io.nats.client.support.Encoding.base32Encode;
import static io.nats.client.support.Encoding.toBase64Url;

public class NatsGenericJwtUtils {

    private static final String ENCODED_CLAIM_HEADER =
            toBase64Url("{\"typ\":\"JWT\", \"alg\":\"ed25519-nkey\"}");
    private static final String accountJwtTemplate = "{ \n" +
                "\"jti\": \"\" , \n" +
                "\"iat\": 0, \n" +
                "\"sub\": \"\", \n" +
                "\"nats\": \"{}\", \n" +
                "\"iss\": \"\" \n" +
            "} \n" ;
    private static final JSONObject genericJwt = new JSONObject(accountJwtTemplate);

    private static void checkKeys(NKey operatorSigningNKey, String operatorSigningId) throws IllegalArgumentException {
        if (operatorSigningNKey.getType() != NKey.Type.OPERATOR) {
            throw new IllegalArgumentException("issueAccountJWT requires an operator key for the operatorSigningKey parameter, but got " + operatorSigningNKey.getType());
        }

        NKey.Type operatorSigningIdType = NKey.fromPublicKey(operatorSigningId.toCharArray()).getType();
        if (operatorSigningIdType != NKey.Type.OPERATOR) {
            throw new IllegalArgumentException("issueAccountJWT requires an operator key for the operatorSigningId parameter, but got " + operatorSigningIdType);
        }

    }

    private static String getJwtBody() throws GeneralSecurityException {
        String encBody = toBase64Url(genericJwt.toString());
        MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
        byte[] encoded = sha256.digest(encBody.getBytes(StandardCharsets.UTF_8));
        genericJwt.put("jti", new String(base32Encode(encoded)));
        return toBase64Url(genericJwt.toString());
    }

    private static String signJwt(NKey operatorSigningNKey, String jwtBody) throws GeneralSecurityException, IOException {
        byte[] sig = (ENCODED_CLAIM_HEADER + "." + jwtBody).getBytes(StandardCharsets.UTF_8);
        return toBase64Url(operatorSigningNKey.sign(sig));
    }

    private static void constructBasicJWT(NKey operatorSigningNKey, String operatorSigningId) {
        checkKeys(operatorSigningNKey, operatorSigningId);
        genericJwt.put("iat", (new Date()).getTime() / 1000L);
        genericJwt.put("iss", operatorSigningId);
        genericJwt.put("sub", operatorSigningId);
    }

    public static String issueGenernicJWTforDeletingAccount(String operatorSigningKey, String operatorSigningId, String[] deletingAccountIds) throws GeneralSecurityException, IOException {
        NKey operatorSigningNKey = NKey.fromSeed(operatorSigningKey.toCharArray());
        constructBasicJWT(operatorSigningNKey, operatorSigningId);
        for (String accountId : deletingAccountIds) {
            NKey.Type accountIdType = NKey.fromPublicKey(accountId.toCharArray()).getType();
            if (accountIdType != NKey.Type.ACCOUNT) {
                throw new IllegalArgumentException("issueAccountJWT requires an account key for the accountId, but got " + accountIdType);
            }
        }
        JSONArray accountsList = new JSONArray();
        JSONObject nats = new JSONObject();
        for (String accountId : deletingAccountIds) {
            accountsList.put(accountId);
        }
        nats.put("accounts",accountsList);
        genericJwt.put("nats", nats);

        String jwtBody = getJwtBody();
        return ENCODED_CLAIM_HEADER + "." + jwtBody + "." + signJwt(operatorSigningNKey, jwtBody);
    }
}
