# 🛡️ Splunk SSH Log Analyzer  

This project demonstrates how a SOC Analyst uses Splunk to analyze **SSH authentication logs** for detecting suspicious activities such as failed logins, brute-force attempts, successful logins from unusual locations, and unauthenticated SSH connections. You’ll learn how to ingest JSON log data, extract key fields, run detection queries, visualize login trends, and configure alerts for high-risk behavior. The project includes step-by-step tasks for identifying failed attempts, multiple failed authentications, suspicious source IPs, and scanning-like behavior. This hands-on lab strengthens core SIEM skills and provides practical experience in threat detection, log analysis, and building dashboards in Splunk.
---

## 🎯 Objective  
Detect and analyze **SSH authentication** activity to identify brute-force attempts, suspicious logins, and anomalous access patterns using Splunk.
---

## 🧩 Lab Setup  
- **Tool:** Splunk cloud  
- **Dataset:** `ssh_log`  
- **Host:** `linuxserver`  
- **Sourcetype:** `_json`  

---

## ⚙️ Task 1: Searching SSH Events  

### 🕵️ Retrieve all SSH logs  
```spl
source="ssh_logs.json" host="linuxserver" index="main" sourcetype="_json"
```

---

## 📊 Task 2: SSH Activity Analysis  

### 🔹 Identify Top Source IPs  
```spl
source="ssh_logs.json" host="linuxserver" index="main" sourcetype="_json"
| top limit=10 id.orig_h
```

---

## ⚠️ Task 3: Analyze Failed Login Attempts   
```spl
source="ssh_logs.json" host="linuxserver" index="main" sourcetype="_json" event_type="Failed SSH Login"
| stats count by id.orig_h
| sort -count
```

---

## ⚠️ Task 4: Detect Multiple Failed Authentication Attempts (Brute Force) 

### 🔹 Detect repeated failures (e.g., more than 5 attempts).
### 🔹 Trigger an alert when any IP attempts more than 5 logins within 10 minutes. 
```spl
source="ssh_logs.json" host="linuxserver" index="main" sourcetype="_json" event_type="Multiple Failed Authentication Attempts"
| stats count by id.orig_h,id.resp_h 
| where count >= 5

```
---

## ⚠️ Task 5: Look for Failure → Success pattern

### 🔹 Correlate successful logins with earlier failures to detect signs of credential misuse or compromise.  
```spl
source="ssh_logs.json" host="linuxserver" index="main" sourcetype="_json" event_type="Successful SSH Login" id.orig_h=164.89.50.183
| stats count by id.orig_h,id.resp_h
| sort -count
```

---

## 🖼 Dashboard Screenshots  

<img width="1920" height="1020" alt="Screenshot 2025-11-02 190203" src="https://github.com/user-attachments/assets/ba81c651-1472-4ff1-bab6-bfa8367c4f7d" />
<img width="1920" height="1020" alt="Screenshot 2025-11-02 191955" src="https://github.com/user-attachments/assets/e216212d-a081-4452-9430-6ce938701d9e" />
<img width="1920" height="1020" alt="Screenshot 2025-11-02 192012" src="https://github.com/user-attachments/assets/639649db-6170-4c6a-a507-e6066b167975" />
<img width="1920" height="1020" alt="Screenshot 2025-11-02 192335" src="https://github.com/user-attachments/assets/347b8921-b440-4ccc-8ddb-99fb863bb3fb" />
<img width="1920" height="1020" alt="Screenshot 2025-11-02 192437" src="https://github.com/user-attachments/assets/046b42c0-652b-4614-8f7d-2fbe40ce447d" />
<img width="1920" height="1020" alt="Screenshot 2025-11-02 192537" src="https://github.com/user-attachments/assets/2ec40af9-2604-4711-a342-5da6e8812c94" />
<img width="1920" height="1020" alt="Screenshot 2025-11-02 192757" src="https://github.com/user-attachments/assets/8c0f1c1c-95e3-4ffa-8770-90c65a27e481" />

---

## 🙌 Acknowledgment  
Special thanks to [Rajneesh Gupta](https://github.com/0xrajneesh/) for the dataset and guidance.

---

## 🏁 Conclusion  
This project helped me:  
- Explore SSH monitoring through Splunk  
- Detect anomalies and failed login spikes  
- Investigate attacker IPs and visualize trends  

---

## 🔖 Tags  
`#Splunk` `#CyberSecurity` `#SOC` `#SIEM` `#SSHLogs` `#ThreatDetection` `#BlueTeam` `#HandsOnLearning`
