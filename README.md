# Windows Endpoint Behavioral Analysis Pipeline

## English

### Overview
A comprehensive security monitoring system designed to detect threats and suspicious behavior on Windows endpoints. This pipeline analyzes Windows security event logs in real-time, applies rule-based detection, and uses machine learning (Isolation Forest) to identify anomalous process execution patterns.

### Features
- **Real-time Event Processing**: Loads and normalizes Windows security events from Event Log sources
- **Rule-Based Detection**: 8 security rules covering common attack patterns:
  - PowerShell execution detection
  - Encoded command arguments (-enc, -encodedcommand)
  - Unusually long command lines (>100 characters)
  - Office macro-based attacks (Word/Excel spawning shells)
  - Known hacking tools (Mimikatz, SharpView, PSExec, Cobalt, Rubeus, etc.)
  - Attack command signatures (Get-ObjectAcl, privileg::debug, sekurlsa, etc.)
  - Unsigned or invalid digital signatures
  - Suspicious DLL loads (from Temp, AppData, ProgramData)
  - Direct LSASS memory access attempts

- **Behavioral Analysis**: Time-window based behavioral features for:
  - Process count per host/user
  - Unique processes per user
  - Command execution frequency
  - Unsigned execution rates

- **Machine Learning**: Isolation Forest algorithm to detect statistical anomalies

- **Interactive Dashboard**: Plotly-based HTML dashboard with:
  - Alert timeline and statistics
  - Top suspicious processes and users
  - LSASS access attempts visualization
  - Behavioral anomaly scores

- **Multi-format Export**: Alerts exported as CSV for further analysis

### Project Structure
```
├── src/
│   ├── dashboard.py         # HTML dashboard generation
│   ├── detection.py         # Rule-based threat detection
│   ├── loader.py            # Data loading and normalization
│   ├── ml.py                # Behavioral ML analysis
│   └── pipeline_v3.py       # Main analysis pipeline
├── data/
│   └── raw/                 # Downloaded dataset storage
├── outputs/
│   ├── alerts_full.json     # All detected alerts
│   ├── aggregated_windows.json # Behavioral features
│   └── dashboard.html       # Interactive visualization
├── uploads/
│   └── requirements.txt     # Python requirements
└── README.md                # This file
```

### Installation
```bash
pip install -r uploads/requirements.txt
```

### Usage

**Run the full analysis pipeline:**
```bash
python src/pipeline_v3.py
```

### Output Files

1. **alerts_full.json** - Complete alert records with all detection flags and scores
2. **aggregated_windows.json** - Behavioral features by host and time window
3. **dashboard.html** - Interactive dashboard showing threat patterns and anomalies

### Detection Rules

| Rule | Description | Severity |
|------|-------------|----------|
| PowerShell Execution | Detects PowerShell process launch | Medium |
| Encoded Commands | Looks for -enc or -encodedcommand flags | High |
| Long Commands | Unusually long command lines (>100 chars) | Medium |
| Office Macro | Office app spawning cmd/PowerShell | High |
| Hacking Tools | Known malware/pentest tools detected | Critical |
| Attack Signatures | Specific MITRE ATT&CK command patterns | Critical |
| Unsigned Code | Missing or invalid digital signatures | High |
| Suspicious DLL Load | DLLs loaded from temp/app directories | High |
| LSASS Access | Direct memory access to LSASS process | Critical |

### Performance
- Processes 1000+ events per second
- Handles datasets with millions of events
- Generates dashboard in <5 seconds on modern hardware

### Use Cases
- **Incident Response**: Quickly identify compromised systems
- **Threat Hunting**: Discover advanced threats missed by traditional AV
- **Compliance Auditing**: Monitor endpoint activity for regulatory requirements
- **Purple Team Exercises**: Validate detection capabilities

### Notes
- The pipeline automatically downloads sample datasets from the OTRF Security-Datasets repository
- All timestamps are normalized to UTC
- Behavioral features use 60-second sliding windows by default
- The Isolation Forest threshold can be adjusted for sensitivity tuning

---

## ไทย

### ภาพรวม
ระบบการเฝ้าระวังความปลอดภัยที่ครอบคลุม ออกแบบมาเพื่อตรวจจับภัยคุกคามและพฤติกรรมที่น่าสงสัยบน Windows endpoints โดยสามารถวิเคราะห์ Windows security event logs แบบเรียลไทม์ ใช้กฎการตรวจจับ และใช้ machine learning (Isolation Forest) เพื่อระบุลักษณะการดำเนินการของ process ที่ผิดปกติ

### คุณสมบัติหลัก
- **ประมวลผลเหตุการณ์แบบเรียลไทม์**: โหลดและทำให้ข้อมูล Windows security events เป็นมาตรฐาน
- **การตรวจจับแบบกฎ**: ระบบ 8 กฎความปลอดภัย ครอบคลุมลักษณะการโจมตีทั่วไป:
  - ตรวจจับการเรียกใช้ PowerShell
  - คำสั่งที่เข้ารหัส (-enc, -encodedcommand)
  - บรรทัดคำสั่งที่ยาวผิดปกติ (>100 อักขระ)
  - การโจมตีแบบ Macro จาก Office (Word/Excel เปิด shell)
  - เครื่องมือแฮคเกอร์ที่รู้จัก (Mimikatz, SharpView, PSExec, Cobalt, Rubeus ฯลฯ)
  - ลายเซ็นคำสั่งโจมตี (Get-ObjectAcl, privileg::debug, sekurlsa ฯลฯ)
  - ลายเซ็นดิจิทัลที่ไม่ถูกต้องหรือหายไป
  - การโหลด DLL ที่น่าสงสัย (จาก Temp, AppData, ProgramData)
  - การเข้าถึงหน่วยความจำ LSASS โดยตรง

- **การวิเคราะห์พฤติกรรม**: ฟีเจอร์พฤติกรรมตามหน้าต่างเวลา:
  - จำนวน process ต่อเจ้าภาพ/ผู้ใช้
  - Unique processes ต่อผู้ใช้
  - ความถี่การเรียกใช้คำสั่ง
  - อัตราการเรียกใช้แบบไม่ลงนาม

- **Machine Learning**: อัลกอริทึม Isolation Forest เพื่อตรวจจับความผิดปกติทางสถิติ

- **แดชบอร์ดแบบโต้ตอบ**: แดชบอร์ด HTML แบบ Plotly ที่มี:
  - ไทม์ไลน์การแจ้งเตือนและสถิติ
  - Process และผู้ใช้ที่น่าสงสัยที่สุด
  - การแสดงภาพความพยายามเข้าถึง LSASS
  - คะแนนความผิดปกติของพฤติกรรม

- **ส่งออกหลายรูปแบบ**: Alert ที่ส่งออกเป็น CSV สำหรับการวิเคราะห์เพิ่มเติม

### โครงสร้างโครงการ
```
├── src/
│   ├── dashboard.py         # สร้างแดชบอร์ด HTML
│   ├── detection.py         # ตรวจจับภัยคุกคามตามกฎเกณฑ์
│   ├── loader.py            # โหลดและจัดการข้อมูล
│   ├── ml.py                # วิเคราะห์พฤติกรรมด้วย ML
│   └── pipeline_v3.py       # Pipeline การวิเคราะห์หลัก
├── data/
│   └── raw/                 # จัดเก็บชุดข้อมูลที่ดาวน์โหลดมา
├── outputs/
│   ├── alerts_full.json     # Alert ที่ตรวจจับทั้งหมด
│   ├── aggregated_windows.json # ฟีเจอร์พฤติกรรม
│   └── dashboard.html       # การแสดงภาพแบบโต้ตอบ
├── uploads/
│   └── requirements.txt     # ความต้องการไลบรารีของ Python
└── README.md                # ไฟล์นี้
```

### การติดตั้ง
```bash
pip install -r uploads/requirements.txt
```

### การใช้งาน

**รัน pipeline การวิเคราะห์หลัก:**
```bash
python src/pipeline_v3.py
```

### ไฟล์เอาท์พุต

1. **alerts_full.json** - บันทึก alert ที่สมบูรณ์พร้อมธงการตรวจจับทั้งหมดและคะแนน
2. **aggregated_windows.json** - ฟีเจอร์พฤติกรรมตามเจ้าภาพและหน้าต่างเวลา
3. **dashboard.html** - แดชบอร์ดแบบโต้ตอบแสดงลักษณะและความผิดปกติของภัยคุกคาม

### กฎการตรวจจับ

| กฎ | คำอธิบาย | ระดับความรุนแรง |
|------|---------|---------|
| PowerShell Execution | ตรวจจับการเปิดใช้ PowerShell | ปานกลาง |
| Encoded Commands | ค้นหาธง -enc หรือ -encodedcommand | สูง |
| Long Commands | บรรทัดคำสั่งที่ยาวผิดปกติ (>100 ตัว) | ปานกลาง |
| Office Macro | Office app เปิด cmd/PowerShell | สูง |
| Hacking Tools | ตรวจจับเครื่องมือแฮคเกอร์ที่รู้จัก | วิกฤต |
| Attack Signatures | ลักษณะคำสั่ง MITRE ATT&CK | วิกฤต |
| Unsigned Code | ลายเซ็นดิจิทัลหายไปหรือไม่ถูกต้อง | สูง |
| Suspicious DLL Load | DLL ที่โหลดจาก temp/app | สูง |
| LSASS Access | การเข้าถึงหน่วยความจำ LSASS | วิกฤต |

### ประสิทธิภาพ
- ประมวลผล 1000+ events ต่อวินาที
- จัดการชุดข้อมูลที่มีสัญญาณนับล้าน
- สร้างแดชบอร์ดใน <5 วินาทีบนฮาร์ดแวร์สมัยใหม่

### กรณีการใช้งาน
- **การตอบสนองต่อเหตุการณ์**: ระบุระบบที่ถูกบุกรุกได้อย่างรวดเร็ว
- **Threat Hunting**: ค้นหาภัยคุกคามขั้นสูงที่ AV ตามเนื้องานพลาด
- **การตรวจสอบ Compliance**: ตรวจสอบกิจกรรม endpoint เพื่อปฏิบัติตามข้อกำหนด
- **Purple Team Exercises**: ตรวจสอบความสามารถในการตรวจจับ

### หมายเหตุ
- Pipeline จะดาวน์โหลดชุดข้อมูลตัวอย่างจากที่เก็บ OTRF Security-Datasets โดยอัตโนมัติ
- ป้ายกำกับเวลาทั้งหมดได้รับการทำให้เป็นมาตรฐานเป็น UTC
- ฟีเจอร์พฤติกรรมใช้หน้าต่างการเลื่อน 60 วินาทีตามค่าเริ่มต้น
- สามารถปรับเกณฑ์ Isolation Forest เพื่อปรับความไวได้

---

**Author**: Security Analyst  
**Last Updated**: 2026-04-08  
**Version**: 2.0
