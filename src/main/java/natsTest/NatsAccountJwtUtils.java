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
public abstract class   NatsAccountJwtUtils {
    private static final String ENCODED_CLAIM_HEADER =
            toBase64Url("{\"typ\":\"JWT\", \"alg\":\"ed25519-nkey\"}");
    private static String jwtAccount = "{\n" +
            "  \"jti\": \"\",\n" +
            "  \"iat\": \"\",\n" +
            "  \"iss\": \"\",\n" +
            "  \"name\": \"\",\n" +
            "  \"sub\": \"\",\n" +
            "  \"nats\": {\n" +
            "    \"limits\": {\n" +
            "      \"subs\": -1,\n" +
            "      \"data\": -1,\n" +
            "      \"payload\": -1,\n" +
            "      \"imports\": -1,\n" +
            "      \"exports\": -1,\n" +
            "      \"wildcards\": true,\n" +
            "      \"conn\": -1,\n" +
            "      \"leaf\": -1,\n" +
            "      \"mem_storage\": -1,\n" +
            "      \"disk_storage\": -1,\n" +
            "      \"streams\": -1,\n" +
            "      \"consumer\": -1\n" +
            "    },\n" +
            "    \"signing_keys\": [\n" +
            "    ],\n" +
            "    \"default_permissions\": {\n" +
            "      \"pub\": {},\n" +
            "      \"sub\": {}\n" +
            "    },\n" +
            "    \"type\": \"account\",\n" +
            "    \"version\": 2\n" +
            "  }\n" +
            "}";
    private static JSONObject jwtAccountJsonObject = new JSONObject(jwtAccount);

    public static String issueAccountJWT(String operatorSigningKey,String operatorSigningId,String accountSigningKey,String accountId, String accountName) throws  GeneralSecurityException, IOException {
        NKey operatorSigningNKey = NKey.fromSeed(operatorSigningKey.toCharArray() );
        if (operatorSigningNKey.getType() != NKey.Type.OPERATOR) {
            throw new IllegalArgumentException("issueAccountJWT requires an operator key for the operatorSigningKey parameter, but got " + operatorSigningNKey.getType());
        }

        NKey.Type operatorSigningIdType = NKey.fromPublicKey(operatorSigningId.toCharArray()).getType();
        if (operatorSigningIdType != NKey.Type.OPERATOR) {
            throw new IllegalArgumentException("issueAccountJWT requires an operator key for the operatorSigningId parameter, but got " + operatorSigningIdType );
        }

        NKey.Type accountSigningKeyType = NKey.fromPublicKey(accountSigningKey.toCharArray()).getType();
        if ( accountSigningKeyType != NKey.Type.ACCOUNT) {
            throw new IllegalArgumentException("issueAccountJWT requires an account key for the accountSigningKey, but got " + accountSigningKeyType );
        }

        NKey.Type accountIdType = NKey.fromPublicKey(accountId.toCharArray()).getType();
        if ( accountIdType != NKey.Type.ACCOUNT) {
            throw new IllegalArgumentException("issueAccountJWT requires an account key for the accountId, but got " + accountIdType );
        }

        jwtAccountJsonObject.put("name", accountName);
        jwtAccountJsonObject.put("iat", (new Date()).getTime() / 1000L);
        jwtAccountJsonObject.put("iss", operatorSigningId);
        jwtAccountJsonObject.put("sub", accountId);

        JSONObject nats = (JSONObject) jwtAccountJsonObject.get("nats");
        ( ( JSONArray ) nats.get("signing_keys")).put(accountSigningKey);

        String encBody = toBase64Url(jwtAccountJsonObject.toString());
        MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
        byte[] encoded = sha256.digest(encBody.getBytes(StandardCharsets.UTF_8));
        jwtAccountJsonObject.put( "jti", new String(base32Encode(encoded)) );

        encBody = toBase64Url(jwtAccountJsonObject.toString());
        byte[] sig = (ENCODED_CLAIM_HEADER + "." + encBody).getBytes(StandardCharsets.UTF_8);
        String encSig = toBase64Url(operatorSigningNKey.sign(sig));

        return ENCODED_CLAIM_HEADER + "." + encBody + "." + encSig;
    }

}
