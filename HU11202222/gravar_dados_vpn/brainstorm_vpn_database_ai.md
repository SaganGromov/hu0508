# Brainstorm: VPN Login Database Opportunities with AI and Generative AI

## 1. Executive summary

The current VPN login database is a strong foundation for corporate remote-access observability. It captures who connected, when, from where, with which device, which authentication method, which VPN tunnel type, and which access group was assigned.

With approximately 10 million records per month, this data can support security monitoring, fraud and insider-risk detection, operational capacity planning, compliance evidence, device governance, access governance, and AI-assisted SOC workflows.

The highest-value opportunities are:

1. Detect anomalous VPN behavior for users, devices, certificates, IPs, access groups, and authentication methods.
2. Build AI-generated risk narratives for SOC analysts and security managers.
3. Provide a natural-language interface for querying VPN activity.
4. Enrich login events with geolocation, threat intelligence, HR/organization metadata, CMDB/device inventory, IAM data, and endpoint posture.
5. Create automated alerts and investigation playbooks for suspicious remote access.
6. Use the database as a trusted source for compliance reports and audit trails.

---

## 2. Current structure observed

### 2.1 Data flow

The implemented flow is:

```text
rsyslog -> login_handler.py -> Redis/Kafka -> vpn_data_writer.py -> DB2
```

The transient operational store is Redis, where each VPN session is accumulated by `session_uid`. The persistent analytical/audit store is DB2.

### 2.2 Main DB2 table

The documentation describes a corporate VPN authentication table, deployed as:

```text
DB2PEP.AUT_CPTV
```

The table stores VPN login/authentication events.

Expected monthly volume:

```text
~10 million rows/month
```

### 2.3 Main captured attributes

| Business concept | DB2 field in documentation | DB2 field in writer | Meaning |
|---|---:|---:|---|
| Sequential identifier | `CD_IDFR_MTA` | `CD_IDFR_AUT` | Unique row identifier |
| Unique session/transaction | `CD_UNCO_TRAN` | `CD_UNCO_AUT` | VPN session identifier |
| Event timestamp | `TS_TRAN` | `TS_TRAN` | Login/auth event timestamp |
| Monthly partition number | `NR_PTC` | `NR_PTC` | Month derived from timestamp |
| Source/origin IP | `CD_END_LGC_OGM` | `CD_END_LGC_OGM` | Public/source IP used by employee |
| Corporate VPN IP | `CD_END_LGC_CPTV` | `CD_END_LGC_CPTV` | Internal VPN IP assigned to device |
| Authentication method | `NM_MTD_AUT` | `NM_MTD_AUT` | Standard, certificate, MDM, app auth, etc. |
| Device hostname | `NM_DSVO` | `NM_DSVO` | Device name |
| MAC address | `CD_END_FSCO` | `CD_END_FSCO` | Physical network address |
| Device identifier | `CD_IDFC_DSVO` | `CD_IDFC_DSVO` | Stable device identifier |
| Certificate/access fingerprint | `CD_IDFC_ACSS` | `CD_IDFC_ACSS` | Certificate/hash fingerprint |
| Operating system | `NM_SO` | `NM_SO` | OS name |
| OS version | `CD_VRS_SO` | `CD_VRS_SO` | OS version |
| Tunnel/protocol | `CD_TIP_CNXO` | `CD_TIP_CNXO` | SSL, IPSec, etc. |
| User/employee ID | `CD_USU` | `CD_USU_AUT` | Corporate user/matricula |
| Access group | `TX_GR_ACSS` | `TX_GR_ACSS` | VPN access group/permission profile |

### 2.4 Important naming discrepancy

There is a mismatch between the Markdown table specification and the implementation guide/script:

| Area | Documentation says | Writer uses |
|---|---:|---:|
| Primary ID | `CD_IDFR_MTA` | `CD_IDFR_AUT` |
| Unique transaction/session | `CD_UNCO_TRAN` | `CD_UNCO_AUT` |
| User ID | `CD_USU` char(9) | `CD_USU_AUT` char(8) |

Before building analytics or AI products, the physical DB2 schema should be treated as the source of truth and the documentation should be reconciled.

---

## 3. What the database can already answer

### 3.1 Security monitoring

- Which employees connected to VPN in a given period.
- Which source IPs are most common.
- Which employees use unusual source IPs.
- Which devices connect most frequently.
- Which certificates/fingerprints are used by which users.
- Whether the same certificate or device appears across multiple employees.
- Whether a user changed device, MAC address, certificate, OS, tunnel type, or authentication method.
- Which access groups are most used.
- Which users are connecting outside expected working hours.
- Which users are connecting with legacy OS versions.
- Which authentication methods are still in use and whether stronger methods are being adopted.

### 3.2 Operational analytics

- Daily/hourly VPN login volume.
- Peak login windows.
- Monthly growth trends.
- Authentication method distribution.
- SSL vs IPSec usage.
- Corporate VPN IP pool consumption patterns.
- Redis-to-DB2 ingestion volume and backlog indicators.
- Device and OS inventory from VPN perspective.

### 3.3 Audit and compliance

- Evidence that a given employee connected at a specific time.
- Historical device/certificate used by an employee.
- Access group assigned at login time.
- Authentication method used at login time.
- Traceability for remote-access incidents.
- Volume and coverage evidence for VPN access governance.

---

## 4. High-value AI and machine learning use cases

### 4.1 User behavior anomaly detection

Train user-specific or peer-group models to identify unusual behavior.

Examples:

- User logs in at a rare hour.
- User logs in from a source IP never seen before.
- User changes authentication method unexpectedly.
- User appears with a new device, MAC address, or certificate.
- User connects with a new OS version or old unsupported OS.
- User starts using an unusual access group.
- User has a sudden spike in number of sessions.

Recommended techniques:

- Isolation Forest.
- Local Outlier Factor.
- One-class SVM.
- Autoencoders for sequence behavior.
- Time-series baselines per user, department, location, and access group.
- Graph-based anomaly detection for user-device-certificate relationships.

### 4.2 Device identity risk scoring

Build a risk score for each device using:

- Device ID.
- Hostname.
- MAC address.
- OS and OS version.
- Certificate fingerprint.
- Number of users associated with the device.
- Number of source IPs associated with the device.
- Number of access groups reached through the device.
- Frequency of authentication method changes.

Possible alerts:

- One device used by many users.
- One user using many devices.
- One certificate fingerprint seen on multiple devices.
- Same MAC address with multiple hostnames.
- Same hostname with multiple MAC addresses.
- Outdated or unsupported OS connecting to sensitive groups.

### 4.3 Credential compromise indicators

Detect signals that may indicate stolen credentials:

- Login from a rare or high-risk IP.
- Login at unusual time followed by another login from a very different network.
- User normally authenticates with certificate but suddenly uses password-based method.
- User appears with a new device and new source IP at the same time.
- New source IP accesses a privileged VPN group.
- Many failed or incomplete login attempts, if failure events are added later.

Recommended enrichment:

- GeoIP/country/city/ASN.
- Known VPN/proxy/Tor/datacenter IP lists.
- Threat intelligence for malicious IPs.
- Corporate HR location or usual work region.

### 4.4 Impossible-travel and unusual-location detection

The current schema has source IP but no geolocation. By enriching `CD_END_LGC_OGM`, the company can detect:

- Logins from impossible geographic distances.
- Logins from countries where the employee does not operate.
- Logins from datacenter, hosting, VPN, proxy, or anonymizer ASNs.
- Rapid movement between unrelated networks.

This is especially useful when combined with:

- Employee home/work region.
- Historical source IPs.
- Corporate travel records, if available and permitted.

### 4.5 Access group risk analytics

`TX_GR_ACSS` is highly valuable because it connects the login event to permissions.

Possible analyses:

- Which access groups have the largest population.
- Which privileged groups are accessed outside business hours.
- Which users changed groups over time.
- Which groups are accessed from unmanaged or unknown devices.
- Which groups are accessed using weaker authentication methods.
- Which groups are associated with legacy OS versions.

AI can learn the normal profile of each access group and flag logins that do not match the expected pattern.

### 4.6 Certificate and fingerprint intelligence

`CD_IDFC_ACSS` can be used to track certificate usage.

Possible detections:

- Certificate reused by more than one user.
- Certificate reused across multiple devices.
- Certificate appears after long inactivity.
- Certificate paired with a new source IP and new device.
- Certificate used with unexpected authentication method.

This can support certificate lifecycle management and incident response.

### 4.7 VPN capacity forecasting

Use historical login volume to forecast:

- Peak concurrent authentication demand.
- Expected daily/monthly volume.
- Growth by department/access group.
- Demand by authentication method.
- Possible saturation of IP pools.

Recommended models:

- Prophet-style time-series forecasting.
- ARIMA/SARIMA.
- Gradient boosted trees with calendar features.
- Neural time-series models for long-term capacity planning.

### 4.8 Data quality AI

Use AI/ML to detect inconsistent or degraded data capture:

- Sudden increase in null source IPs.
- Sudden increase in null device IDs.
- New unexpected values in authentication method.
- Hostnames with abnormal formats.
- OS version values outside known catalog.
- Access group values with broken encoding or unexpected truncation.
- Spike in events without `session_uid`.

This can detect parser failures, upstream changes, and logging regressions.

---

## 5. Generative AI opportunities

### 5.1 SOC analyst copilot

A GenAI assistant can help analysts investigate VPN alerts.

Example prompts:

- "Explain why this VPN login was flagged as risky."
- "Summarize this user's VPN behavior over the last 30 days."
- "Compare this login to the user's normal pattern."
- "Show other users who used the same device or certificate."
- "Generate an incident timeline for this session."
- "Draft a case note for the SOC ticket."

Important: the model should not directly receive raw credentials, secrets, or unnecessary personally identifiable information. Use controlled retrieval, masking, and approved internal models where required.

### 5.2 Natural-language database querying

Create a text-to-SQL interface for approved analysts.

Example questions:

- "Which users connected from new IPs yesterday?"
- "Show employees who used more than three devices this month."
- "Which access groups had logins outside business hours?"
- "Find certificates used by multiple users."
- "List VPN logins from unsupported OS versions."
- "What was the hourly login peak last Monday?"

Recommended safeguards:

- Read-only SQL only.
- Row-level and column-level access controls.
- Query approval for sensitive fields.
- SQL generation validation.
- Result-size limits.
- Audit log of every prompt, generated SQL, and result access.

### 5.3 Executive summaries

Generate weekly or monthly summaries:

- VPN usage trend.
- Top risk indicators.
- Authentication method adoption.
- Legacy OS exposure.
- New devices and certificates.
- Privileged group remote access.
- Data quality issues.
- Recommended remediation actions.

These summaries can be tailored for:

- SOC managers.
- Infrastructure teams.
- IAM teams.
- Compliance/audit.
- Executive leadership.

### 5.4 AI-generated incident timelines

For a suspicious login, GenAI can assemble:

- First time the user/device/certificate appeared.
- Previous source IPs.
- Access group involved.
- Authentication method.
- Other users sharing device/certificate/IP.
- Related logins in the same time window.
- Suggested next investigation steps.

The system should cite exact database rows or query IDs so analysts can verify every statement.

### 5.5 Playbook and response recommendation

Based on risk patterns, GenAI can suggest actions:

- Ask user to confirm activity.
- Temporarily disable VPN access.
- Revoke certificate.
- Force password reset.
- Require step-up MFA.
- Open endpoint investigation.
- Check EDR telemetry for the device.
- Review access group membership.
- Block source IP/ASN if malicious.

The AI should recommend, not execute, unless integrated with approved SOAR workflows and human approval.

### 5.6 Policy gap discovery

GenAI can analyze aggregated trends and suggest policy improvements:

- "Users in privileged groups should not authenticate with weaker methods."
- "Devices with unsupported OS should be blocked from VPN."
- "Certificates used by multiple users should be reviewed."
- "Access groups with high volume from unmanaged devices need segmentation."
- "Source IPs from hosting providers should trigger step-up authentication."

---

## 6. Recommended data enrichments

The current schema is useful, but AI value increases significantly with enrichment.

### 6.1 Identity enrichment

Join `CD_USU` / `CD_USU_AUT` to:

- Employee directory.
- Department.
- Role/function.
- Manager.
- Work location.
- Employment status.
- Privileged-user flag.
- Contractor/employee flag.
- Expected working schedule.

### 6.2 Device enrichment

Join device identifiers to:

- CMDB.
- MDM.
- EDR.
- Asset owner.
- Device compliance status.
- Encryption status.
- Patch status.
- Last vulnerability scan.
- Managed/unmanaged status.

### 6.3 Network enrichment

Enrich source IP with:

- Country, region, city.
- ASN and ISP.
- Residential vs corporate vs datacenter.
- Known proxy/VPN/Tor status.
- Threat intelligence reputation.
- First-seen and last-seen dates.

### 6.4 IAM/access enrichment

Join access groups to:

- Business application scope.
- Privilege level.
- Data classification.
- Owner.
- Approval workflow.
- Criticality.

### 6.5 Authentication enrichment

If available, add:

- Login success/failure.
- Failure reason.
- MFA challenge result.
- Risk score from identity provider.
- Certificate validity/expiration.
- Device posture result.
- Logout/disconnect timestamp.
- Session duration.

---

## 7. Additional tables or views worth creating

### 7.1 Dimension tables

Suggested dimensions:

- `DIM_USUARIO`
- `DIM_DISPOSITIVO`
- `DIM_CERTIFICADO`
- `DIM_GRUPO_ACESSO`
- `DIM_IP_ORIGEM`
- `DIM_SISTEMA_OPERACIONAL`
- `DIM_METODO_AUTENTICACAO`
- `DIM_TEMPO`

These make analytics faster, cleaner, and easier for AI systems to query safely.

### 7.2 Feature tables for ML

Create daily or hourly feature tables such as:

- `FEATURE_USUARIO_DIA`
- `FEATURE_DISPOSITIVO_DIA`
- `FEATURE_CERTIFICADO_DIA`
- `FEATURE_IP_DIA`
- `FEATURE_GRUPO_ACESSO_DIA`

Example features:

- Count of sessions.
- Count of distinct devices.
- Count of distinct source IPs.
- Count of distinct certificates.
- First/last login time.
- Weekend/holiday login flag.
- New source IP flag.
- New device flag.
- New certificate flag.
- Rare authentication method flag.
- Privileged access group flag.
- Unsupported OS flag.

### 7.3 Risk scoring table

Create a table to store computed risk:

```text
VPN_LOGIN_RISK_SCORE
```

Suggested columns:

- Session identifier.
- User identifier.
- Timestamp.
- Numeric risk score.
- Risk category.
- Triggered rules/features.
- Model version.
- Explanation text.
- Analyst feedback.
- False-positive flag.

### 7.4 Analyst feedback table

AI systems improve when analysts label outcomes.

Suggested labels:

- True positive.
- False positive.
- Benign known behavior.
- Confirmed compromise.
- Policy violation.
- Data quality issue.

This can support supervised learning and model tuning.

---

## 8. Recommended dashboards

### 8.1 Security dashboard

- Risky logins by day.
- New devices by user.
- New source IPs by user.
- Certificates used by multiple users.
- Privileged access outside business hours.
- Legacy OS access.
- Unusual authentication method changes.

### 8.2 Operations dashboard

- Login volume by hour/day/month.
- Top authentication methods.
- Top tunnel types.
- VPN IP pool usage.
- DB2 insert rate.
- Redis backlog.
- Parser/data quality metrics.

### 8.3 Governance dashboard

- Access group usage.
- Users in sensitive groups.
- Devices accessing sensitive groups.
- Authentication method compliance by group.
- OS compliance by group.
- Dormant users who still connect.

---

## 9. Example analytics questions

### 9.1 User and device

- Which users connected from a new device this week?
- Which devices are used by more than one employee?
- Which employees used more than three devices in 30 days?
- Which certificates are shared across users or devices?
- Which users changed authentication method recently?

### 9.2 IP and geography

- Which users connected from a new source IP?
- Which source IPs are used by many employees?
- Which source IPs are from datacenter networks?
- Which VPN logins came from high-risk countries?
- Which users logged in from impossible travel patterns?

### 9.3 Access and privilege

- Which privileged access groups were used outside business hours?
- Which users recently started using a new access group?
- Which access groups are accessed by unmanaged devices?
- Which access groups still allow weaker authentication methods?

### 9.4 Operations

- What are peak VPN login hours?
- How is VPN usage growing month over month?
- Are there ingestion gaps between Redis and DB2?
- Are null fields increasing after a parser or infrastructure change?

---

## 10. Data governance and privacy considerations

This database contains sensitive security and employee access data.

Recommended controls:

- Classify the table as sensitive security telemetry.
- Limit raw access to approved teams.
- Mask employee identifiers where full identity is not needed.
- Hash or tokenize sensitive identifiers for model training where possible.
- Keep clear retention rules.
- Audit all queries.
- Separate production data from AI experimentation data.
- Avoid sending raw records to external AI services.
- Use internal/private model endpoints for GenAI use cases.
- Require explainability for automated risk scores.
- Keep human approval for high-impact actions such as account suspension or certificate revocation.

---

## 11. Technical improvements to support AI

### 11.1 Schema and data modeling

- Reconcile physical column names between documentation and implementation.
- Confirm primary key and indexes in DB2.
- Add or confirm index on `TS_TRAN`.
- Add or confirm index on session UID.
- Add or confirm indexes on user, source IP, device ID, certificate fingerprint, and access group.
- Consider partitioning by date/month beyond `NR_PTC` if supported by the DB2 environment.
- Consider adding load timestamp and source system metadata.
- Consider adding event type/status if future logs include logout/failure events.

### 11.2 Ingestion reliability

- Avoid `MAX(id) + 1` as a long-term ID generation strategy at high volume; prefer DB2 identity/sequence if possible.
- Track ingestion lag from Redis score/time to DB2 insert time.
- Add duplicate protection at DB2 level using a unique constraint on session UID if the event model allows it.
- Add dead-letter handling for invalid records.
- Monitor null rates and schema drift.
- Keep parser version and writer version in operational logs.

### 11.3 AI platform readiness

- Build curated analytical views that expose only approved columns.
- Create feature tables with stable definitions.
- Version ML features and models.
- Store model explanations and analyst feedback.
- Create a controlled retrieval layer for GenAI.
- Add prompt and response audit logging for GenAI tools.
- Require citations from AI-generated summaries to exact query results.

---

## 12. Suggested implementation roadmap

### Phase 1: Foundation

1. Validate the real DB2 schema and reconcile documentation.
2. Confirm keys, indexes, partitioning, and retention.
3. Build core dashboards for volume, users, devices, IPs, authentication methods, and access groups.
4. Add data quality monitoring for nulls, unexpected values, and ingestion gaps.

### Phase 2: Enrichment

1. Add GeoIP/ASN enrichment for source IPs.
2. Join employee directory metadata.
3. Join CMDB/MDM/EDR device metadata.
4. Classify access groups by sensitivity.
5. Add threat intelligence enrichment for source IPs.

### Phase 3: Detection

1. Create rule-based detections for obvious risks.
2. Build user/device/certificate baselines.
3. Add anomaly scoring.
4. Store risk scores and explanations.
5. Add analyst feedback labels.

### Phase 4: Generative AI

1. Build a read-only natural-language query assistant over curated views.
2. Generate automated daily/weekly VPN security summaries.
3. Create AI-generated incident timelines.
4. Add SOC copilot functions with citations and approved playbooks.
5. Use analyst feedback to improve recommendations.

### Phase 5: Automation

1. Integrate with SIEM/SOAR.
2. Trigger tickets for high-confidence alerts.
3. Recommend account/device/certificate actions.
4. Add human approval workflows.
5. Measure false positives, response time, and prevented incidents.

---

## 13. Highest-priority quick wins

1. Reconcile DB2 column names in `tabela_vpn.md`, `implantacao_vpn_data_writer.md`, and `vpn_data_writer.py`.
2. Create a daily dashboard of VPN login volume, unique users, unique devices, unique source IPs, auth methods, and access groups.
3. Add detections for:
   - New source IP per user.
   - New device per user.
   - Certificate used by multiple users.
   - Privileged group access outside business hours.
   - Unsupported OS versions.
4. Enrich source IP with GeoIP/ASN.
5. Create a risk score table with explanation fields.
6. Build a GenAI weekly summary that uses only aggregated and approved data.
7. Build a read-only text-to-SQL assistant for approved analysts using curated views.

---

## 14. Final assessment

The current VPN login table is already valuable for audit, monitoring, and investigation. Its biggest strength is that it links user, timestamp, source IP, corporate IP, authentication method, device, certificate fingerprint, OS, tunnel type, and access group in a single event.

The biggest current limitation is that it appears to capture login/authentication events but not the full session lifecycle, such as logout time, duration, success/failure reason, MFA result, endpoint compliance, or downstream application access. Adding enrichment and derived feature tables will unlock much stronger AI use cases.

The most practical AI strategy is to start with transparent anomaly detection and GenAI-assisted investigation summaries, then evolve toward risk scoring, natural-language querying, and supervised models using analyst feedback.
