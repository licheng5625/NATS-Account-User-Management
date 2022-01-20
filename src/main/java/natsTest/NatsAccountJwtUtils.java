package natsTest;
import io.nats.client.NKey;
import org.json.JSONArray;
import org.json.JSONObject;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.util.Date;
import java.util.List;

import static io.nats.client.support.Encoding.base32Encode;
import static io.nats.client.support.Encoding.toBase64Url;
public class NatsAccountJwtUtils {

    private static final String ENCODED_CLAIM_HEADER =
            toBase64Url("{\"typ\":\"JWT\", \"alg\":\"ed25519-nkey\"}");
    private static final String accountJwtTemplate = "{\n" +
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
    private static final JSONObject accountJwt = new JSONObject(accountJwtTemplate);

    private static void checkKeys(NKey operatorSigningNKey, String operatorSigningId, String accountSigningKey, String accountId) throws IllegalArgumentException {
        if (operatorSigningNKey.getType() != NKey.Type.OPERATOR) {
            throw new IllegalArgumentException("issueAccountJWT requires an operator key for the operatorSigningKey parameter, but got " + operatorSigningNKey.getType());
        }

        NKey.Type operatorSigningIdType = NKey.fromPublicKey(operatorSigningId.toCharArray()).getType();
        if (operatorSigningIdType != NKey.Type.OPERATOR) {
            throw new IllegalArgumentException("issueAccountJWT requires an operator key for the operatorSigningId parameter, but got " + operatorSigningIdType);
        }

        NKey.Type accountSigningKeyType = NKey.fromPublicKey(accountSigningKey.toCharArray()).getType();
        if (accountSigningKeyType != NKey.Type.ACCOUNT) {
            throw new IllegalArgumentException("issueAccountJWT requires an account key for the accountSigningKey, but got " + accountSigningKeyType);
        }

        NKey.Type accountIdType = NKey.fromPublicKey(accountId.toCharArray()).getType();
        if (accountIdType != NKey.Type.ACCOUNT) {
            throw new IllegalArgumentException("issueAccountJWT requires an account key for the accountId, but got " + accountIdType);
        }
    }

    private static String getJwtBody() throws GeneralSecurityException {
        String encBody = toBase64Url(accountJwt.toString());
        MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
        byte[] encoded = sha256.digest(encBody.getBytes(StandardCharsets.UTF_8));
        accountJwt.put("jti", new String(base32Encode(encoded)));
        return toBase64Url(accountJwt.toString());
    }

    private static String signJwt(NKey operatorSigningNKey, String jwtBody) throws GeneralSecurityException, IOException {
        byte[] sig = (ENCODED_CLAIM_HEADER + "." + jwtBody).getBytes(StandardCharsets.UTF_8);
        return toBase64Url(operatorSigningNKey.sign(sig));
    }

    public static void constructBasicJWT(NKey operatorSigningNKey, String operatorSigningId, String accountSigningKey, String accountId, String accountName) {
        checkKeys(operatorSigningNKey, operatorSigningId, accountSigningKey, accountId);
        accountJwt.put("name", accountName);
        accountJwt.put("iat", (new Date()).getTime() / 1000L);
        accountJwt.put("iss", operatorSigningId);
        accountJwt.put("sub", accountId);
        JSONObject nats = (JSONObject) accountJwt.get("nats");
        ((JSONArray) nats.get("signing_keys")).put(accountSigningKey);
    }

    public static String issueAccountJWT(String operatorSigningKey, String operatorSigningId, String accountSigningKey, String accountId, String accountName) throws GeneralSecurityException, IOException {
        NKey operatorSigningNKey = NKey.fromSeed(operatorSigningKey.toCharArray());
        constructBasicJWT(operatorSigningNKey, operatorSigningId, accountSigningKey, accountId, accountName);
        String jwtBody = getJwtBody();
        return ENCODED_CLAIM_HEADER + "." + jwtBody + "." + signJwt(operatorSigningNKey, jwtBody);
    }

    public static String issueAccountJWT(String operatorSigningKey, String operatorSigningId, String accountSigningKey, String accountId, String accountName, List<NatsImportRule> imports) throws GeneralSecurityException, IOException {
        NKey operatorSigningNKey = NKey.fromSeed(operatorSigningKey.toCharArray());
        constructBasicJWT(operatorSigningNKey, operatorSigningId, accountSigningKey, accountId, accountName);
        JSONObject nats = (JSONObject) accountJwt.get("nats");
        JSONArray importRules = new JSONArray();
        for (NatsImportRule importRule : imports) {
            JSONObject rule = new JSONObject();
            if (importRule.account != null) {
                rule.put("account", importRule.account);
            }
            rule.put("name", importRule.name);
            rule.put("subject", importRule.subject);
            NatsImportRule.Types sd = importRule.type;
            String sd2 = sd.toString();
            rule.put("type", importRule.type.toString());
            importRules.put(rule);
        }
        nats.put("imports", importRules);
        String jwtBody = getJwtBody();
        return ENCODED_CLAIM_HEADER + "." + jwtBody + "." + signJwt(operatorSigningNKey, jwtBody);
    }
}
