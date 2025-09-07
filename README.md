# GuruTvapay Java SDK — `GuruTvapayClient.java`

A single-file Java SDK for integrating with the **GuruTvapay Payment Gateway**. This SDK provides API-key and OAuth (password grant) modes, payment initiation, transaction queries, and webhook verification.

---

## Requirements

* Java 11 or higher (uses `java.net.http.HttpClient`).
* Jackson Databind for JSON parsing.

### Maven dependency

```xml
<dependencies>
  <dependency>
    <groupId>com.fasterxml.jackson.core</groupId>
    <artifactId>jackson-databind</artifactId>
    <version>2.15.2</version>
  </dependency>
</dependencies>
```

### Gradle dependency

```gradle
implementation 'com.fasterxml.jackson.core:jackson-databind:2.15.2'
```

---

## Installation

1. Copy `GuruTvapayClient.java` into your project under `src/main/java/com/gurutvapay/sdk/`.
2. Add Jackson dependency to your build tool (Maven/Gradle).

---

## Quickstart — API-key mode (recommended)

```java
import com.gurutvapay.sdk.GuruTvapayClient;
import com.fasterxml.jackson.databind.JsonNode;
import java.util.Map;

public class Example {
    public static void main(String[] args) throws Exception {
        GuruTvapayClient client = new GuruTvapayClient("uat", System.getenv("GURUTVA_API_KEY"), null, null);

        JsonNode payment = client.createPayment(Map.of(
            "amount", 100,
            "merchantOrderId", "ORD" + System.currentTimeMillis(),
            "channel", "web",
            "purpose", "Online Payment",
            "customer", Map.of("buyer_name", "John Doe", "email", "john@example.com", "phone", "9876543210")
        ), null);

        System.out.println(payment.toPrettyString());
    }
}
```

Run with:

```bash
mvn compile exec:java -Dexec.mainClass=Example
```

---

## OAuth (password grant) example

```java
GuruTvapayClient client = new GuruTvapayClient(
    "uat",
    null,
    System.getenv("GURUTVA_CLIENT_ID"),
    System.getenv("GURUTVA_CLIENT_SECRET")
);

JsonNode token = client.loginWithPassword(System.getenv("GURUTVA_USERNAME"), System.getenv("GURUTVA_PASSWORD"));
System.out.println(token);

JsonNode payment = client.createPayment(Map.of(
    "amount", 200,
    "merchantOrderId", "ORD" + System.currentTimeMillis(),
    "channel", "web",
    "purpose", "OAuth Payment",
    "customer", Map.of("buyer_name", "Alice", "email", "alice@example.com", "phone", "9999999999")
), null);
System.out.println(payment);
```

---

## Transaction status

```java
JsonNode status = client.transactionStatus("ORDER_2024_001");
System.out.println(status.toPrettyString());
```

## Transaction list

```java
JsonNode list = client.transactionList(50, 0);
System.out.println(list.toPrettyString());
```

---

## Idempotency

Add an `Idempotency-Key` header when creating payments:

```java
Map<String, String> headers = Map.of("Idempotency-Key", java.util.UUID.randomUUID().toString());
JsonNode payment = client.createPayment(payload, headers);
```

---

## Webhook verification

```java
String payload = "{\"merchantOrderId\":\"ORD123\",\"status\":\"success\"}";
String signature = "sha256=<hex value>"; // received from GuruTvapay header
String secret = System.getenv("GURUTVA_WEBHOOK_SECRET");

boolean ok = GuruTvapayClient.verifyWebhook(payload.getBytes(StandardCharsets.UTF_8), signature, secret);
System.out.println("Verified: " + ok);
```

---

## API surface

* `GuruTvapayClient(String env, String apiKey, String clientId, String clientSecret)`
* `JsonNode loginWithPassword(String username, String password)`
* `JsonNode createPayment(Map<String,Object> payload, Map<String,String> headers)`
* `JsonNode transactionStatus(String merchantOrderId)`
* `JsonNode transactionList(int limit, int page)`
* `JsonNode request(String method, String pathOrUrl, Map<String,String> headers, String body)`
* `static boolean verifyWebhook(byte[] payload, String signatureHeader, String secret)`

---

## Error handling

* Errors are thrown as `IOException`, `InterruptedException`, or `IllegalStateException`.
* Wrap calls in try/catch to handle gracefully.

---

## Environment variables (recommended)

```
GURUTVA_ENV=uat
GURUTVA_API_KEY=sk_test_xxx
GURUTVA_CLIENT_ID=CLIENT_12345
GURUTVA_CLIENT_SECRET=SECRET_67890
GURUTVA_USERNAME=john@example.com
GURUTVA_PASSWORD=your_password
GURUTVA_WEBHOOK_SECRET=secret123
```

---

## Security

* Never hardcode secrets in code.
* Always verify webhook signatures.
* Use HTTPS in production.

---

## Next steps

* Package this into a JAR and publish to Maven Central.
* Add typed POJOs instead of generic `JsonNode`.
* Add unit tests and CI pipeline.

---

## License

Choose an appropriate license (MIT recommended for SDKs).
