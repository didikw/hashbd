# Incident Response Runbook — SLA Timeout & NIST SP 800-61 Mapping

**Tujuan dokumen:** Menyediakan playbook operasional dengan timeout per tahap yang bisa langsung diimplementasikan sebagai automation rule di SOAR (Security Orchestration, Automation and Response) atau ticketing system (Jira Service Management, ServiceNow, PagerDuty, TheHive, Splunk SOAR, dsb), sekaligus dipetakan ke fase incident handling NIST SP 800-61 Rev. 2.

---

## 1. Klasifikasi Severity (Prasyarat Sebelum Timeout Berlaku)

Timeout SLA hanya bermakna kalau severity classification-nya konsisten. Gunakan matrix ini sebagai trigger awal saat tiket/alert dibuat.

| Severity | Kriteria | Contoh |
|---|---|---|
| **P1 – Critical** | Bukti aktif eksfiltrasi data, ransomware berjalan, akses admin/root dikuasai attacker, layanan produksi down akibat serangan | Ransomware encryption terdeteksi, domain admin compromised |
| **P2 – High** | Intrusi terkonfirmasi tapi belum ada dampak luas, lateral movement terdeteksi, credential dump ditemukan | Malware C2 beacon aktif, akun privileged login dari lokasi anomali |
| **P3 – Medium** | Aktivitas mencurigakan butuh investigasi, belum ada konfirmasi kompromis | Multiple failed login, port scanning dari luar, phishing email diklik tapi payload belum jalan |
| **P4 – Low** | Pelanggaran kebijakan, risiko rendah, tidak ada indikasi kompromis aktif | User install software tidak sah, false positive dari signature lama |

**Field yang wajib di-set di tiket/alert saat dibuat (untuk SOAR trigger):**
- `severity` (P1–P4)
- `incident_type` (malware, phishing, unauthorized_access, dos, data_exfil, policy_violation, dll)
- `detection_source` (SIEM, EDR, IDS/IPS, user_report, threat_intel)
- `first_detected_at` (timestamp) — ini jadi basis perhitungan semua timer di bawah

---

## 2. Playbook per Tahap dengan Timeout

Struktur di bawah mengikuti 4 fase besar NIST SP 800-61: **Preparation → Detection & Analysis → Containment/Eradication/Recovery → Post-Incident Activity**. Tiap tahap punya SLA timer dan aturan eskalasi otomatis.

### Tahap A — Triage & Analisis Awal (Detection & Analysis)

| Severity | SLA Acknowledge | SLA Analisis Selesai | Aksi jika timeout terlampaui |
|---|---|---|---|
| P1 | 5 menit | 15 menit | Auto-escalate ke IC (Incident Commander) + on-call manager, trigger paging (SMS/call, bukan cuma email) |
| P2 | 15 menit | 1 jam | Auto-escalate ke senior analyst, notifikasi Slack/Teams channel #security-incidents |
| P3 | 1 jam | 4 jam | Reassign ke analyst berikutnya di rotation, notifikasi email ke team lead |
| P4 | 4 jam | 1 hari kerja | Masuk antrian normal, reminder otomatis di ticketing |

**Logic SOAR yang perlu dibuat:**
```
IF status == "new" AND time_elapsed(first_detected_at) > SLA_acknowledge[severity]
  THEN trigger_escalation(level=1, channel=paging)
  AND log_sla_breach(stage="triage_acknowledge")

IF status == "in_analysis" AND time_elapsed(analysis_start) > SLA_analysis[severity]
  THEN trigger_escalation(level=2, channel=notify_lead)
  AND flag_ticket(tag="sla_breach_analysis")
```

### Tahap B — Containment (Short-term & Long-term)

| Severity | SLA Containment Awal (isolasi cepat) | SLA Containment Penuh | Aksi jika timeout terlampaui |
|---|---|---|---|
| P1 | 15 menit (network isolation/kill-switch) | 1 jam | Auto-trigger EDR isolate-host action, page CISO/IC, buka war-room bridge otomatis |
| P2 | 1 jam | 8 jam | Escalate ke Incident Commander, wajib approval manual untuk containment lanjutan |
| P3 | 4 jam | 1 hari kerja | Reminder ke analyst, eskalasi jika 2x SLA terlampaui |
| P4 | 1 hari kerja | 3 hari kerja | Masuk backlog remediation terjadwal |

**Catatan implementasi:** Untuk P1, containment awal idealnya **automated response** (bukan menunggu manusia) — misal EDR/XDR langsung isolate endpoint begitu confidence score indicator tinggi. Manusia baru approve untuk containment lanjutan (network segmentation lebih luas, disable akun domain-wide) karena punya blast radius lebih besar.

```
IF severity == "P1" AND stage == "containment_initial" AND time_elapsed > 15min
  THEN auto_execute(action="isolate_host", require_approval=false)
  AND notify(role="IC", role="CISO", method="phone_call")

IF severity == "P2" AND stage == "containment_full" AND time_elapsed > 8h
  THEN escalate(role="incident_commander")
  AND require_manual_approval(action="network_wide_containment")
```

### Tahap C — Eradication & Recovery

| Severity | SLA Eradication | SLA Recovery/Restore Service | Aksi jika timeout terlampaui |
|---|---|---|---|
| P1 | 4 jam | 8 jam | Eskalasi ke leadership, mulai pertimbangkan business continuity plan / DR activation |
| P2 | 1 hari kerja | 2 hari kerja | Eskalasi ke team lead, review ulang root cause analysis |
| P3 | 3 hari kerja | 5 hari kerja | Reminder otomatis, masuk laporan mingguan |
| P4 | 5 hari kerja | Sesuai maintenance window | Tidak perlu eskalasi khusus |

### Tahap D — Post-Incident Activity

| Aktivitas | SLA | Trigger otomatis |
|---|---|---|
| Post-incident review / lessons learned meeting | Dijadwalkan dalam 5 hari kerja setelah insiden ditutup (wajib untuk P1/P2) | Auto-create calendar invite saat ticket status = "resolved" |
| Laporan resmi ke stakeholder/regulator (jika relevan) | Sesuai regulasi (mis. 72 jam untuk breach notification di banyak yurisdiksi — cek regulasi lokal yang berlaku) | Auto-flag compliance team saat `incident_type == data_exfil` |
| Update playbook/detection rule berdasarkan temuan | 2 minggu setelah RCA selesai | Task otomatis ke detection engineering team |
| Ticket ditutup formal | Setelah semua checklist di atas selesai | Manual close, tidak auto-close |

---

## 3. Mapping Matrix ke NIST SP 800-61 Rev. 2

| Fase NIST SP 800-61 | Aktivitas dalam Runbook Ini | KPI Terkait | Timeout SLA (ringkas) |
|---|---|---|---|
| **1. Preparation** | Definisi severity matrix, playbook, staffing on-call, tooling SOAR/SIEM siap, tabletop exercise | — (bukan bagian timer real-time, tapi prasyarat) | Review playbook tiap kuartal |
| **2. Detection & Analysis** | Alert masuk → triage → klasifikasi severity → analisis awal (Tahap A) | **MTTD** (waktu attack mulai s/d alert dikonfirmasi), **MTTR** (alert s/d aksi respons pertama) | P1: 15 menit / P2: 1 jam / P3: 4 jam / P4: 1 hari kerja |
| **3. Containment, Eradication & Recovery** | Isolasi awal → containment penuh → hapus artifact/malware → restore layanan (Tahap B & C) | **MTTC** (respons s/d ancaman tertahan sepenuhnya) | P1: 1 jam (containment) / 8 jam (recovery) |
| **4. Post-Incident Activity** | RCA, lessons learned, update detection rule, laporan compliance (Tahap D) | Time-to-RCA-completion, jumlah playbook update per insiden | 5 hari kerja untuk review meeting |

**Catatan penting soal mapping:**
- NIST 800-61 sebenarnya menggambarkan **Containment, Eradication, dan Recovery sebagai satu fase tunggal** yang iteratif (bukan linear) — di dokumen ini saya pecah jadi tahap terpisah (B dan C) supaya SLA timer-nya bisa diukur dan di-automate secara granular. Ini penyesuaian praktis, bukan penyimpangan dari framework.
- MTTD/MTTR/MTTC bukan istilah resmi dari NIST 800-61 — itu adalah KPI industri (umum dipakai di laporan Mandiant, IBM, Gartner) yang kita petakan ke fase NIST supaya reporting ke leadership dan compliance audit bisa saling nyambung.

---

## 4. Rekomendasi Field & Struktur Tiket untuk Implementasi SOAR/Ticketing

Supaya timeout di atas bisa dieksekusi otomatis, tiket/case perlu minimal field berikut (contoh untuk Jira Service Management / TheHive / ServiceNow SecOps):

```
case.severity            : enum [P1, P2, P3, P4]
case.detected_at          : timestamp
case.acknowledged_at      : timestamp (null sampai analyst ambil kasus)
case.analysis_started_at  : timestamp
case.analysis_completed_at: timestamp
case.containment_initial_at: timestamp
case.containment_full_at  : timestamp
case.eradication_at       : timestamp
case.recovery_at          : timestamp
case.closed_at            : timestamp
case.sla_breach_flags     : array (tag otomatis tiap kali SLA terlampaui, untuk reporting)
case.escalation_log        : array (siapa dinotifikasi, kapan, via channel apa)
```

**Automation rule dasar** (pseudocode, adaptasi ke syntax platform SOAR kamu — Splunk SOAR pakai Playbook Editor, TheHive pakai Cortex responder, ServiceNow pakai Flow Designer):

```
ON case.created:
  SET sla_timer[stage="acknowledge"] = SLA_table[case.severity]["acknowledge"]
  START countdown_timer(sla_timer)

ON countdown_timer.expired AND case.acknowledged_at == null:
  EXECUTE escalate(channel=paging, role=on_call_lead)
  APPEND case.sla_breach_flags += "acknowledge_breach"

ON case.status_changed TO "containment_initial":
  SET sla_timer[stage="containment_initial"] = SLA_table[case.severity]["containment_initial"]
  IF case.severity == "P1":
    EXECUTE auto_action(playbook="isolate_host_edr", approval_required=false)
```

---

## 5. Ringkasan Timer (Quick Reference untuk Runbook Cetak/Wallboard)

| Tahap | P1 Critical | P2 High | P3 Medium | P4 Low |
|---|---|---|---|---|
| Acknowledge | 5 min | 15 min | 1 jam | 4 jam |
| Analisis selesai | 15 min | 1 jam | 4 jam | 1 hari kerja |
| Containment awal | 15 min | 1 jam | 4 jam | 1 hari kerja |
| Containment penuh | 1 jam | 8 jam | 1 hari kerja | 3 hari kerja |
| Eradication | 4 jam | 1 hari kerja | 3 hari kerja | 5 hari kerja |
| Recovery | 8 jam | 2 hari kerja | 5 hari kerja | sesuai maintenance window |
| Post-incident review | 5 hari kerja (wajib) | 5 hari kerja (wajib) | opsional | opsional |

---

## Catatan Penerapan

- **Angka di atas adalah starting point, bukan angka final.** Sesuaikan dengan baseline historis organisasi kamu dan kapasitas tim SOC — target yang tidak realistis justru bikin banyak SLA breach palsu dan tim jadi desensitized terhadap alert.
- **Automated containment untuk P1 punya risiko false-positive** (misal host penting ke-isolate karena salah deteksi) — pastikan ada allowlist untuk asset kritikal (domain controller, database produksi) yang butuh approval manual meski severity P1.
- **Regulasi breach notification** (GDPR 72 jam, UU PDP Indonesia, dsb) punya timeline sendiri di luar SLA internal ini — pastikan compliance/legal team terhubung ke automation trigger di Tahap D, jangan sampai SLA internal malah bikin telat lapor ke regulator.
- Review dan kalibrasi ulang timeout ini setiap kuartal berdasarkan data SLA breach aktual dari ticketing system.
