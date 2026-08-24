# =============================================================================
# Zeek Signatures — WSTG 10 (Business Logic Testing)
# Total rules: 32
# MITRE ATT&CK: T1190, T1078, T1548, T1567, T1485
# Compliance: PCI-DSS 6.5, GDPR 32, HIPAA 164.312, NIST SI-4
# =============================================================================

@load base/frameworks/signatures/main
@load base/protocols/http/software

# =============================================================================
# Business Logic - Price Manipulation
# =============================================================================

signature ZK-WSTG1001 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /(POST|PUT|PATCH) \/(api\/v1\/(cart|order|checkout|payment|purchase))/ regex
	payload /.*"(price|amount|total|cost|fee|charge)"\s*:\s*-[0-9]+.*/ regex
	event "WSTG-10-01: Negative price manipulation in cart/checkout"
}

signature ZK-WSTG1002 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /(POST|PUT|PATCH) \/(api\/v1\/(cart|order|checkout))/ regex
	payload /.*"(price|amount|total|cost|fee)"\s*:\s*(0|0\.00|0\.0).*/ regex
	event "WSTG-10-01: Zero price manipulation in cart/checkout"
}

signature ZK-WSTG1003 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /(POST|PUT|PATCH) \/(api\/v1\/(cart|order|checkout))/ regex
	payload /.*"(quantity|qty|count)"\s*:\s*-[0-9]+.*/ regex
	event "WSTG-10-01: Negative quantity manipulation in cart"
}

signature ZK-WSTG1004 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /(POST|PUT|PATCH) \/(api\/v1\/(cart|order))/ regex
	payload /.*"(discount|coupon|promo|voucher)"\s*:\s*(100|1[0-9]{2,}|[2-9][0-9]{2,}).*/ regex
	event "WSTG-10-01: Excessive discount/coupon manipulation - 100%+ discount"
}

# =============================================================================
# Business Logic - Quantity Exploitation
# =============================================================================

signature ZK-WSTG1005 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /(POST|PUT|PATCH) \/(api\/v1\/(cart|order))/ regex
	payload /.*"(quantity|qty|count)"\s*:\s*[0-9]{7,}.*/ regex
	event "WSTG-10-02: Excessive quantity in cart - integer overflow risk"
}

signature ZK-WSTG1006 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /(POST|PUT|PATCH) \/(api\/v1\/(cart|order))/ regex
	payload /.*"(quantity|qty|count)"\s*:\s*(999999999|2147483647|4294967295).*/ regex
	event "WSTG-10-02: Maximum integer value in quantity field - overflow attack"
}

# =============================================================================
# Business Logic - Race Condition
# =============================================================================

signature ZK-WSTG1007 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /(POST|PUT) \/(api\/v1\/(transfer|payment|withdraw|redeem|claim))/ regex
	payload /.*"(amount|value|credits|points)"\s*:\s*[0-9]+.*/ regex
	event "WSTG-10-03: Financial transaction - race condition risk on transfer/payment"
}

signature ZK-WSTG1008 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /(POST) \/(api\/v1\/(coupon|promo|voucher|gift|reward|referral)\/(redeem|apply|use|claim))/ regex
	event "WSTG-10-03: Coupon/voucher redemption - race condition risk"
}

# =============================================================================
# Business Logic - Workflow Bypass
# =============================================================================

signature ZK-WSTG1009 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /(POST|PUT|PATCH) \/(api\/v1\/order\/\d+\/(ship|deliver|complete|approve))/ regex
	http-header /Authorization: Bearer .*/ regex
	payload /.*"(status|state)"\s*:\s*"(shipped|delivered|completed|approved)".*/ regex
	event "WSTG-10-04: Order status bypass - direct status manipulation"
}

signature ZK-WSTG1010 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /(POST|PUT) \/(api\/v1\/(workflow|approval|review)\/\d+\/(approve|reject|complete))/ regex
	payload /.*"(status|state|decision)"\s*:\s*"(approved|completed|accepted)".*/ regex
	event "WSTG-10-04: Workflow bypass - direct approval/completion without authorization"
}

signature ZK-WSTG1011 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /POST \/(api\/v1\/(order|purchase|checkout|payment))/ regex
	http-header /!(Authorization)/ regex
	event "WSTG-10-04: Order creation without authentication - workflow bypass"
}

# =============================================================================
# Business Logic - Privilege Escalation via Business Logic
# =============================================================================

signature ZK-WSTG1012 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /(PUT|PATCH) \/api\/v1\/users\/\d+/ regex
	payload /.*"(role|isAdmin|permissions|privileges|account_type)"\s*:\s*"(admin|superuser|manager|premium)".*/ regex
	event "WSTG-10-05: Role/privilege modification via user update API"
}

signature ZK-WSTG1013 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /(POST|PUT|PATCH) \/api\/v1\/(subscription|plan|account)/ regex
	payload /.*"(plan|tier|level|type)"\s*:\s*"(premium|enterprise|pro|platinum)".*/ regex
	event "WSTG-10-05: Subscription plan escalation via API parameter manipulation"
}

signature ZK-WSTG1014 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /(GET|DELETE) \/api\/v1\/(users|accounts|orders|transactions)\/\d+/ regex
	payload /.*\d{3,}.*/ regex
	http-response /200 OK/ regex
	event "WSTG-10-05: Sequential IDOR - accessing other user resources by numeric ID"
}

# =============================================================================
# Business Logic - Data Exfiltration
# =============================================================================

signature ZK-WSTG1015 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /(GET|POST) \/api\/v1\/(export|download|report|dump|backup)/ regex
	http-header /Authorization: Bearer .*/ regex
	event "WSTG-10-06: Bulk data export endpoint accessed"
}

signature ZK-WSTG1016 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /GET \/api\/v1\/(users|accounts|customers|records)\?(.*&)?(limit=|per_page=|page_size=|count=)(10000|100000|1000000|all|unlimited|-1)/ regex
	event "WSTG-10-06: Excessive data retrieval - large limit parameter"
}

signature ZK-WSTG1017 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /(GET) \/api\/v1\/(users|accounts|customers|records)\?(.*&)?(fields=|include=|expand=).*(password|token|secret|ssn|credit_card|bank_account)/ regex
	event "WSTG-10-06: Sensitive field enumeration via API parameter"
}

# =============================================================================
# Business Logic - Anti-Automation
# =============================================================================

signature ZK-WSTG1018 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /POST \/(api\/v1\/(register|signup|create-account|otp|verify|reset-password))/ regex
	http-header /User-Agent: .*(python-requests|curl|wget|HTTPie|http\.rb|java\/|Go-http|node-fetch|axios)/ regex
	event "WSTG-10-07: Automated account registration/verification attempt"
}

signature ZK-WSTG1019 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /POST \/(api\/v1\/(transfer|payment|withdraw|redeem|claim))/ regex
	http-header /X-Forwarded-For: .*/ regex
	http-header /!(X-CSRF-Token|X-Request-Id)/ regex
	event "WSTG-10-07: Financial transaction without CSRF protection or request ID"
}

# =============================================================================
# Business Logic - Time-Based Attacks
# =============================================================================

signature ZK-WSTG1020 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /(POST|PUT) \/(api\/v1\/(auction|bid|offer|reservation|booking))/ regex
	payload /.*"(timestamp|time|date|created_at|expires_at)"\s*:\s*"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}".*/ regex
	event "WSTG-10-08: Client-provided timestamp in time-sensitive operation"
}

signature ZK-WSTG1021 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /(POST|PUT) \/(api\/v1\/(coupon|promo|discount|offer|sale)\/(apply|validate|redeem))/ regex
	payload /.*"(valid_from|valid_until|expiry|start_date|end_date)"\s*:\s*".*/ regex
	event "WSTG-10-08: Client-provided date validation in offer/coupon application"
}

# =============================================================================
# Business Logic - Payment Manipulation
# =============================================================================

signature ZK-WSTG1022 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /(POST|PUT) \/(api\/v1\/(payment|charge|transaction|purchase))/ regex
	payload /.*"(currency|amount)"\s*:\s*"(USD|EUR|GBP|JPY)"\s*,\s*"(amount|value)"\s*:\s*[0-9]+.*/ regex
	event "WSTG-10-09: Payment with potentially manipulated currency/amount"
}

signature ZK-WSTG1023 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /(POST|PUT) \/(api\/v1\/payment|api\/v1\/transaction)/ regex
	payload /.*"(merchant_id|recipient_id|destination|to)"\s*:\s*"[^"]*".*/ regex
	event "WSTG-10-09: Payment recipient manipulation - possible payee swap"
}

# =============================================================================
# Business Logic - Refund/Return Abuse
# =============================================================================

signature ZK-WSTG1024 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /(POST) \/(api\/v1\/(refund|return|cancel|reversal|chargeback))/ regex
	payload /.*"(amount|value|credit)"\s*:\s*[0-9]{4,}.*/ regex
	event "WSTG-10-10: Refund/return with abnormally high amount"
}

signature ZK-WSTG1025 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /(POST) \/(api\/v1\/(refund|return|cancel))/ regex
	payload /.*"(order_id|transaction_id|reference)"\s*:\s*"[^"]*".*/ regex
	event "WSTG-10-10: Refund request for potentially manipulated order reference"
}

# =============================================================================
# Business Logic - Account Takeover via Business Logic
# =============================================================================

signature ZK-WSTG1026 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /(POST) \/(api\/v1\/(password-reset|forgot-password|recover-account))/ regex
	payload /.*"(email|phone|username)"\s*:\s*"[^"]*".*/ regex
	http-header /User-Agent: .*(python-requests|curl|wget|Go-http|node-fetch)/ regex
	event "WSTG-10-11: Automated password reset attempt - account takeover risk"
}

signature ZK-WSTG1027 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /(PUT|PATCH) \/api\/v1\/users\/\d+\/(email|phone|password)/ regex
	http-header /Authorization: Bearer .*/ regex
	payload /.*"(email|phone|new_email|new_phone)"\s*:\s*"[^"]*".*/ regex
	event "WSTG-10-11: Email/phone change request - account takeover attempt"
}

# =============================================================================
# Business Logic - Rate Limiting Bypass
# =============================================================================

signature ZK-WSTG1028 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /POST \/(api\/v1\/(login|auth|signin|verify|otp|sms|email-verification))/ regex
	http-header /X-Forwarded-For: .*/ regex
	event "WSTG-10-12: Rate limit bypass attempt via X-Forwarded-For header rotation"
}

signature ZK-WSTG1029 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /POST \/(api\/v1\/(login|auth|signin))/ regex
	http-header /X-Real-IP: .*/ regex
	event "WSTG-10-12: Rate limit bypass attempt via X-Real-IP header"
}

# =============================================================================
# Business Logic - IDOR via Business Object
# =============================================================================

signature ZK-WSTG1030 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /GET \/api\/v1\/(invoices|receipts|statements|documents)\/[A-Z]{2}[0-9]{6,}/ regex
	http-response /200 OK/ regex
	event "WSTG-10-13: Predictable document ID access - business object IDOR"
}

signature ZK-WSTG1031 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /GET \/api\/v1\/(orders|transactions|payments)\/\d{4,}/ regex
	http-header /Authorization: Bearer .*/ regex
	event "WSTG-10-13: Sequential numeric order/transaction ID accessed - IDOR"
}

signature ZK-WSTG1032 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /(PUT|PATCH|DELETE) \/api\/v1\/(orders|transactions|payments|accounts)\/\d+/ regex
	http-header /Authorization: Bearer .*/ regex
	http-response /200 OK|204 No Content/ regex
	event "WSTG-10-13: Modification of business object by sequential ID - IDOR"
}