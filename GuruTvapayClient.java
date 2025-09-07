// GuruTvapayClient.java
// Java 11+ single-file SDK for GuruTvapay
// Requires Jackson databind on the classpath (Maven dependency shown below)

package com.gurutvapay.sdk;

import java.io.IOException;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.util.Map;
import java.util.StringJoiner;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

/**
 * Single-file Java SDK client for GuruTvapay.
 *
 * Usage:
 *  - Put this file in src/main/java/com/gurutvapay/sdk/GuruTvapayClient.java
 *  - Add Jackson dependency (see Maven snippet below)
 *  - Compile & run on Java 11+
 */
public class GuruTvapayClient {

    private static final String DEFAULT_ROOT = "https://api.gurutvapay.com";
    private static final String ENV_PREFIX_UAT = "/uat_mode";
    private static final String ENV_PREFIX_LIVE = "/live";

    private final HttpClient http;
    private final ObjectMapper mapper;
    private final String root;
    private final String env; // "uat" or "live"
    private final String envPrefix;

    private final String apiKey;
    private final String clientId;
    private final String clientSecret;

    // OAuth token state (optional)
    private String accessToken;
    private long tokenExpiresAtEpochSec;

    // retry settings (simple)
    private final int maxRetries = 3;
    private final int backoffMillis = 500;

    public GuruTvapayClient(String env, String apiKey, String clientId, String clientSecret) {
        if (!"uat".equals(env) && !"live".equals(env)) throw new IllegalArgumentException("env must be 'uat' or 'live'");
        this.env = env;
        this.envPrefix = "uat".equals(env) ? ENV_PREFIX_UAT : ENV_PREFIX_LIVE;
        this.root = DEFAULT_ROOT;
        this.apiKey = apiKey;
        this.clientId = clientId;
        this.clientSecret = clientSecret;
        this.http = HttpClient.newHttpClient();
        this.mapper = new ObjectMapper();
    }

    // -----------------------
    // Auth helper
    // -----------------------
    private String authHeader() {
        if (apiKey != null && !apiKey.isEmpty()) return "Bearer " + apiKey;
        if (accessToken != null && Instant.now().getEpochSecond() < tokenExpiresAtEpochSec - 10) return "Bearer " + accessToken;
        return null;
    }

    /**
     * Perform password grant login and store token in client.
     * Returns parsed JSON response.
     */
    public JsonNode loginWithPassword(String username, String password) throws IOException, InterruptedException {
        if (clientId == null || clientSecret == null) throw new IllegalStateException("clientId/clientSecret required for OAuth login");
        String url = root + envPrefix + "/login";

        var form = Map.of(
            "grant_type", "password",
            "username", username,
            "password", password,
            "client_id", clientId,
            "client_secret", clientSecret
        );
        String formBody = formEncode(form);

        HttpRequest req = HttpRequest.newBuilder(URI.create(url))
            .header("Content-Type", "application/x-www-form-urlencoded")
            .POST(HttpRequest.BodyPublishers.ofString(formBody))
            .build();

        JsonNode resp = sendWithRetries(req);
        if (resp.has("access_token")) {
            accessToken = resp.get("access_token").asText();
            if (resp.has("expires_at")) {
                tokenExpiresAtEpochSec = resp.get("expires_at").asLong();
            } else if (resp.has("expires_in")) {
                tokenExpiresAtEpochSec = Instant.now().getEpochSecond() + resp.get("expires_in").asLong();
            } else {
                tokenExpiresAtEpochSec = Instant.now().getEpochSecond() + 3600;
            }
        }
        return resp;
    }

    // -----------------------
    // High-level API methods
    // -----------------------

    /**
     * createPayment -> POST /initiate-payment (root)
     * payload fields: amount, merchantOrderId, channel, purpose, customer {...}
     */
    public JsonNode createPayment(Map<String, Object> payload, Map<String, String> extraHeaders) throws IOException, InterruptedException {
        String url = root + "/initiate-payment";
        String body = mapper.writeValueAsString(payload);
        var builder = HttpRequest.newBuilder(URI.create(url))
            .header("Content-Type", "application/json")
            .POST(HttpRequest.BodyPublishers.ofString(body));

        String auth = authHeader();
        if (auth != null) builder.header("Authorization", auth);
        if (extraHeaders != null) extraHeaders.forEach(builder::header);

        return sendWithRetries(builder.build());
    }

    /**
     * transactionStatus -> POST /{envPrefix}/transaction-status (form-encoded)
     */
    public JsonNode transactionStatus(String merchantOrderId) throws IOException, InterruptedException {
        String url = root + envPrefix + "/transaction-status";
        String formBody = "merchantOrderId=" + urlEncode(merchantOrderId);
        var builder = HttpRequest.newBuilder(URI.create(url))
            .header("Content-Type", "application/x-www-form-urlencoded")
            .POST(HttpRequest.BodyPublishers.ofString(formBody));
        String auth = authHeader();
        if (auth != null) builder.header("Authorization", auth);
        return sendWithRetries(builder.build());
    }

    /**
     * transactionList -> GET /{envPrefix}/transaction-list?limit=..&page=..
     */
    public JsonNode transactionList(int limit, int page) throws IOException, InterruptedException {
        String url = String.format("%s%s/transaction-list?limit=%d&page=%d", root, envPrefix, limit, page);
        var builder = HttpRequest.newBuilder(URI.create(url)).GET();
        String auth = authHeader();
        if (auth != null) builder.header("Authorization", auth);
        return sendWithRetries(builder.build());
    }

    /**
     * Generic request to arbitrary path or absolute URL.
     * Returns parsed JSON node (or throws).
     */
    public JsonNode request(String method, String pathOrUrl, Map<String, String> headers, String body) throws IOException, InterruptedException {
        String url = pathOrUrl.startsWith("http") ? pathOrUrl : root + (pathOrUrl.startsWith("/") ? "" : "/") + pathOrUrl;
        var builder = HttpRequest.newBuilder(URI.create(url));
        if (method.equalsIgnoreCase("GET")) builder.GET();
        else if (method.equalsIgnoreCase("POST")) builder.POST(HttpRequest.BodyPublishers.ofString(body == null ? "" : body));
        else builder.method(method.toUpperCase(), HttpRequest.BodyPublishers.ofString(body == null ? "" : body));

        if (headers != null) headers.forEach(builder::header);
        String auth = authHeader();
        if (auth != null) builder.header("Authorization", auth);
        return sendWithRetries(builder.build());
    }

    // -----------------------
    // Webhook verification (HMAC-SHA256)
    // -----------------------
    public static boolean verifyWebhook(byte[] payload, String signatureHeader, String secret) {
        if (signatureHeader == null || signatureHeader.isEmpty()) return false;
        String sigHex = signatureHeader.startsWith("sha256=") ? signatureHeader.substring(7) : signatureHeader;
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(secret.getBytes(StandardCharsets.UTF_8), "HmacSHA256"));
            byte[] computed = mac.doFinal(payload);
            byte[] provided = hexToBytes(sigHex);
            if (provided == null || provided.length != computed.length) return false;
            // constant-time compare
            int diff = 0;
            for (int i = 0; i < computed.length; i++) diff |= (computed[i] ^ provided[i]);
            return diff == 0;
        } catch (NoSuchAlgorithmException | InvalidKeyException e) {
            throw new RuntimeException(e);
        }
    }

    // -----------------------
    // Low-level: send with retries
    // -----------------------
    private JsonNode sendWithRetries(HttpRequest req) throws IOException, InterruptedException {
        int attempt = 0;
        while (true) {
            attempt++;
            HttpResponse<String> resp;
            try {
                resp = http.send(req, HttpResponse.BodyHandlers.ofString());
            } catch (IOException | InterruptedException ex) {
                if (attempt >= maxRetries) throw ex;
                Thread.sleep(backoffMillis * (1L << (attempt - 1)));
                continue;
            }

            int sc = resp.statusCode();
            String body = resp.body();
            if (sc >= 200 && sc < 300) {
                if (body == null || body.isBlank()) return mapper.createObjectNode();
                return mapper.readTree(body);
            }
            if (sc == 401 || sc == 403) {
                throw new IOException("Authentication error: " + sc + " - " + body);
            }
            if (sc == 404) throw new IOException("Not found: " + req.uri());
            if (sc == 429) {
                // try Retry-After
                String ra = resp.headers().firstValue("Retry-After").orElse(null);
                if (ra != null) {
                    long wait = 1000;
                    try { wait = Long.parseLong(ra) * 1000L; } catch (Exception ignore) {}
                    if (attempt < maxRetries) { Thread.sleep(wait); continue; }
                }
                throw new IOException("Rate limited: " + body);
            }
            if (sc >= 500 && attempt < maxRetries) {
                Thread.sleep(backoffMillis * (1L << (attempt - 1)));
                continue;
            }
            throw new IOException("HTTP " + sc + ": " + body);
        }
    }

    // -----------------------
    // Helpers
    // -----------------------
    private static String urlEncode(String s) { return URLEncoder.encode(s, StandardCharsets.UTF_8); }

    private static String formEncode(Map<String, String> map) {
        StringJoiner j = new StringJoiner("&");
        for (var e : map.entrySet()) {
            j.add(urlEncode(e.getKey()) + "=" + urlEncode(e.getValue()));
        }
        return j.toString();
    }

    private static byte[] hexToBytes(String hex) {
        if (hex == null || (hex.length() % 2) != 0) return null;
        int len = hex.length() / 2;
        byte[] out = new byte[len];
        for (int i = 0; i < len; i++) out[i] = (byte) Integer.parseInt(hex.substring(2*i, 2*i+2), 16);
        return out;
    }

    // -----------------------
    // Example main (quick test)
    // -----------------------
    public static void main(String[] args) throws Exception {
        // Read from env vars (recommended)
        String env = System.getenv().getOrDefault("GURUTVA_ENV", "uat");
        String apiKey = System.getenv("GURUTVA_API_KEY");
        String clientId = System.getenv("GURUTVA_CLIENT_ID");
        String clientSecret = System.getenv("GURUTVA_CLIENT_SECRET");

        GuruTvapayClient client = new GuruTvapayClient(env, apiKey, clientId, clientSecret);

        // Example: create payment with API key mode
        if (apiKey != null && !apiKey.isBlank()) {
            var payload = Map.<String,Object>of(
                "amount", 100,
                "merchantOrderId", "ORD" + System.currentTimeMillis(),
                "channel", "web",
                "purpose", "Test Payment",
                "customer", Map.of("buyer_name","Java User","email","java@example.com","phone","9999999999")
            );
            JsonNode resp = client.createPayment(payload, null);
            System.out.println(\"createPayment response: \" + resp.toPrettyString());
        } else if (clientId != null && clientSecret != null) {
            // Example: login + create payment
            System.out.println(\"No API key; trying OAuth password grant (set GURUTVA_USERNAME/PASSWORD env vars)\");
            String username = System.getenv(\"GURUTVA_USERNAME\");
            String password = System.getenv(\"GURUTVA_PASSWORD\");
            if (username == null || password == null) {
                System.err.println(\"Please set GURUTVA_USERNAME and GURUTVA_PASSWORD for OAuth flow.\");
                return;
            }
            JsonNode tok = client.loginWithPassword(username, password);
            System.out.println(\"login response: \" + tok.toPrettyString());
            var payload = Map.<String,Object>of(
                "amount", 101,
                "merchantOrderId", "ORD" + System.currentTimeMillis(),
                "channel", "web",
                "purpose", "OAuth Test",
                "customer", Map.of("buyer_name","OAuth User","email","oauth@example.com","phone","9999999999")
            );
            JsonNode resp = client.createPayment(payload, null);
            System.out.println(\"createPayment response: \" + resp.toPrettyString());
        } else {
            System.err.println(\"Set either GURUTVA_API_KEY or GURUTVA_CLIENT_ID/GURUTVA_CLIENT_SECRET env vars.\");
        }

        // Example webhook verification
        String secret = System.getenv().getOrDefault(\"GURUTVA_WEBHOOK_SECRET\",\"changeme\");
        String payload = \"{\\\"merchantOrderId\\\": \\\"ORD123\\\", \\\"status\\\": \\\"success\\\"}\"; // example
        // simulate sig with HMAC-SHA256
        Mac mac = Mac.getInstance(\"HmacSHA256\");
        mac.init(new SecretKeySpec(secret.getBytes(StandardCharsets.UTF_8), \"HmacSHA256\"));
        byte[] comp = mac.doFinal(payload.getBytes(StandardCharsets.UTF_8));
        StringBuilder sb = new StringBuilder();
        for (byte b : comp) sb.append(String.format(\"%02x\", b));
        String header = \"sha256=\" + sb.toString();
        boolean ok = verifyWebhook(payload.getBytes(StandardCharsets.UTF_8), header, secret);
        System.out.println(\"Webhook verify simulated result: \" + ok);
    }
}
