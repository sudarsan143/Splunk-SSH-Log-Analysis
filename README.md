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

## ⚠️ Task 6: Detect suspicious unauthenticated SSH connection attempts.  
```spl
source="ssh_logs.json" host="linuxserver" index="main" sourcetype="_json" event_type="Connection Without Authentication" id.orig_h=164.89.50.183 
| stats count by id.orig_h,id.resp_h 
| sort -count
```

---

## 🖼 Dashboard Screenshots 

![image alt](https://github.com/sudarsan143/Splunk-SSH-Log-Analysis/blob/c64cc500665d9b762b053bc59e815af4a5776b2c/Analyze%20Failed%20Login%20Attempts.png)
![image alt](https://github.com/sudarsan143/Splunk-SSH-Log-Analysis/blob/c64cc500665d9b762b053bc59e815af4a5776b2c/Failed%20Login%20chart.png)
![image alt](https://github.com/sudarsan143/Splunk-SSH-Log-Analysis/blob/c64cc500665d9b762b053bc59e815af4a5776b2c/Detect%20Multiple%20Failed%20Authentication%20Attempts%20(Brute%20Force).png)
![image alt](https://github.com/sudarsan143/Splunk-SSH-Log-Analysis/blob/c64cc500665d9b762b053bc59e815af4a5776b2c/Failure%20%E2%86%92%20Success%20pattern.png)
![image alt](https://github.com/sudarsan143/Splunk-SSH-Log-Analysis/blob/c64cc500665d9b762b053bc59e815af4a5776b2c/suspicious%20unauthenticated%20SSH%20connection%20attempts..png)
![image alt](https://github.com/sudarsan143/Splunk-SSH-Log-Analysis/blob/c64cc500665d9b762b053bc59e815af4a5776b2c/splunk%20ssh_logs%20dashboard.png)


---



---

## 🏁 Conclusion  
This project enabled me to deepen my SOC analysis skills by:  
- Performing comprehensive SSH authentication monitoring using Splunk 
- Identifying brute-force patterns, anomalous login behaviors, and suspicious access attempts
- Correlating successful logins with prior failures to uncover potential account compromise
- Profiling attacker IPs through geo-enrichment and interpreting trends with dashboards and time-based visualizations 

---
---

## 🏁 Final Thoughts  
- This project strengthened my practical SOC workflow by simulating real-world SSH attack scenarios and investigating them through Splunk. From detecting brute-force attempts to analyzing authenticated sessions, the end-to-end process reinforced how SIEM data can reveal early signs of compromise. The dashboards, alerts, and correlation logic built during this project provide a strong foundation for continuous monitoring and rapid incident response in an enterprise environment.


---

## 🔖 Tags  
`#Splunk` `#CyberSecurity` `#SOC` `#SIEM` `#SSHLogs` `#ThreatDetection` `#BlueTeam` `#HandsOnLearning`
