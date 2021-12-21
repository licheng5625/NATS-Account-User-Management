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

public abstract class NatsUserJwtUtils {
    private static final String ENCODED_CLAIM_HEADER =
            toBase64Url("{\"typ\":\"JWT\", \"alg\":\"ed25519-nkey\"}");
    private static String jwtUser = "{ \n" +
                "\"jti\": \"\" , \n" +
                "\"iat\": 0, \n" +
                "\"iss\": \"\", \n" +
                "\"name\": \"\", \n" +
                "\"sub\": \"\", \n" +
                "\"nats\": { \n" +
                "\"pub\": {}, \n" +
                "\"sub\": {}, \n" +
                "\"subs\": -1, \n" +
                "\"data\": -1, \n" +
                "\"payload\": -1, \n" +
                "\"issuer_account\": \"\", \n" +
                "\"type\": \"user\", \n" +
                "\"version\": 2 \n" +
                "} \n" +
                "} \n" ;
    public static JSONObject jwtUserJsonObject = new JSONObject(jwtUser);
    public static String issueUserJWT(NKey accountSigningKey,String accountId, String publicUserKey, String userName) throws GeneralSecurityException, IOException {
        if (accountSigningKey.getType() != NKey.Type.ACCOUNT) {
            throw new IllegalArgumentException("issueUserJWT requires an account key for the accountSigningKey parameter, but got " + accountSigningKey.getType());
        }
        // Validate the accountId:
        NKey accountKey = NKey.fromPublicKey(accountId.toCharArray());
        if (accountKey.getType() != NKey.Type.ACCOUNT) {
            throw new IllegalArgumentException("issueUserJWT requires an account key for the accountId parameter, but got " + accountKey.getType());
        }
        // Validate the publicUserKey:
        NKey userKey = NKey.fromPublicKey(publicUserKey.toCharArray());
        if (userKey.getType() != NKey.Type.USER) {
            throw new IllegalArgumentException("issueUserJWT requires a user key for the publicUserKey, but got " + userKey.getType());
        }

        jwtUserJsonObject.put("name", userName);
        jwtUserJsonObject.put("iat",  (new Date()).getTime() / 1000L);
        jwtUserJsonObject.put("iss", new String(accountSigningKey.getPublicKey()));
        jwtUserJsonObject.put("sub", publicUserKey);
        ((JSONObject) jwtUserJsonObject.get("nats")).put("issuer_account",accountId);

        String claimJson = jwtUserJsonObject.toString();
        // Compute jti, a base32 encoded sha256 hash
        MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
        byte[] encoded = sha256.digest(claimJson.getBytes(StandardCharsets.UTF_8));
        jwtUserJsonObject.put("jti", new String(base32Encode(encoded)));

        claimJson = jwtUserJsonObject.toString();
        // all three components (header/body/signature) are base64url encoded
        String encBody = toBase64Url(claimJson);

        // compute the signature off of header + body (. included on purpose)
        byte[] sig = (ENCODED_CLAIM_HEADER + "." + encBody).getBytes(StandardCharsets.UTF_8);
        String encSig = toBase64Url(accountSigningKey.sign(sig));

        // append signature to header and body and return it
        return ENCODED_CLAIM_HEADER + "." + encBody + "." + encSig;
    }



}
