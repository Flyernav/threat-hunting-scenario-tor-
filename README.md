<img width="400" src="https://github.com/user-attachments/assets/44bac428-01bb-4fe9-9d85-96cba7698bee" alt="Tor Logo with the onion and a crosshair on it"/>

# Threat Hunt Report: Unauthorized TOR Usage
- [Scenario Creation](https://github.com/Flyernav/threat-hunting-scenario-tor-/blob/main/threat-hunting-scenario-tor-event-creation.md)

## Platforms and Languages Leveraged
- Windows 10 Virtual Machines (Microsoft Azure)
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)
- Tor Browser

##  Scenario

Management suspects that some employees may be using TOR browsers to bypass network security controls because recent network logs show unusual encrypted traffic patterns and connections to known TOR entry nodes. Additionally, there have been anonymous reports of employees discussing ways to access restricted sites during work hours. The goal is to detect any TOR usage and analyze related security incidents to mitigate potential risks. If any use of TOR is found, notify management.

### High-Level TOR-Related IoC Discovery Plan

- **Check `DeviceFileEvents`** for any `tor(.exe)` or `firefox(.exe)` file events.
- **Check `DeviceProcessEvents`** for any signs of installation or usage.
- **Check `DeviceNetworkEvents`** for any signs of outgoing connections over known TOR ports.

---

## Steps Taken

### 1. Searched the `DeviceFileEvents` Table

Searched for any file that had the string "tor" in it and discovered what looks like the user "labuser" downloaded a TOR installer, did something that resulted in many TOR-related files being copied to the desktop, and the creation of a file called `tor-shopping-list.txt` on the desktop at `2025-05-22T23:52:05.7090523Z`. These events began at `2025-05-22T23:32:51.5651801Z`.

**Query used to locate events:**

```kql
DeviceFileEvents
| where DeviceName == "trey-final-thre"
| where InitiatingProcessAccountName == "labuser"
| where FileName contains "tor"
| where Timestamp  >= datetime(2025-05-22T23:10:33.5621375Z)
| order by Timestamp desc
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, Account  = InitiatingProcessAccountName

```
<![torlabpic1](https://github.com/user-attachments/assets/e80636ba-03bd-4278-8f16-2380bce0deac)>

---

### 2. Searched the `DeviceProcessEvents` Table

Searched for any `ProcessCommandLine` that contained the string "tor-browser-windows-x86_64-portable-14.0.1.exe". Based on the logs returned, at `2025-05-22T23:38:35.3535155Z`, an employee on the "trey-final-thre" device ran the file `tor-browser-windows-x86_64-portable-14.0.1.exe` from their Downloads folder, using a command that triggered a silent installation.

**Query used to locate event:**

```kql

DeviceProcessEvents
| where DeviceName == "trey-final-thre"
| where ProcessCommandLine contains "tor-browser-windows-x86_64-portable-14.5.2.exe"
| project Timestamp, AccountName, ActionType, DeviceName, FileName, SHA256, ProcessCommandLine

```
<![torlabpic2](https://github.com/user-attachments/assets/5d8db3f1-69d0-4ba7-b4be-fd38ba94cef0)>

---

### 3. Searched the `DeviceProcessEvents` Table for TOR Browser Execution

Searched for any indication that user "labuser" actually opened the TOR browser. There was evidence that they did open it at `2025-05-22T23:39:03.2555774Z`. There were several other instances of `firefox.exe` (TOR) as well as `tor.exe` spawned afterwards.

**Query used to locate events:**

```kql
DeviceProcessEvents
| where DeviceName == "trey-final-thre"
| where FileName has_any ("tor.exe", "firefox.exe", "tor-browser.exe")
| order by Timestamp desc
| project Timestamp, AccountName, ActionType, FolderPath , DeviceName, FileName, SHA256, ProcessCommandLine
```
<![torlabpic3](https://github.com/user-attachments/assets/f00f8fba-dcc9-4cf5-9e05-b21c73037cfc)>

---

### 4. Searched the `DeviceNetworkEvents` Table for TOR Network Connections

Searched for any indication the TOR browser was used to establish a connection using any of the known TOR ports. At `2025-05-22T23:39:13.2643557Z`, an employee on the "trey-final-thre" device successfully established a connection to the remote IP address `37.48.90.84` on port `9001`. The connection was initiated by the process `tor.exe`, located in the folder `c:\users\employee\desktop\tor browser\browser\torbrowser\tor\tor.exe`. There were a couple of other connections to sites over port `443`.

**Query used to locate events:**

```kql
DeviceNetworkEvents
| where DeviceName == "trey-final-thre"
| where InitiatingProcessAccountName != "system"
| where RemotePort in ("9001", "9030", "9040", "9050", "9051", "9150")
| project Timestamp, DeviceName, InitiatingProcessAccountName, ActionType, RemoteIP, RemotePort, RemoteUrl, InitiatingProcessFolderPath
| order by Timestamp desc

```
<![torlabpic4](https://github.com/user-attachments/assets/0382cdbf-c974-4ec7-8afb-b55937190a82)>


---

## Chronological Event Timeline 

Date: May 22, 2025

🕓 11:32:51 PM UTC
Initial Activity Detected
File activity begins related to "tor" on the Desktop.


A user labeled “labuser” appears to have downloaded a Tor Browser installer or initiated an action that led to the presence of multiple Tor-related files on the system.



🕓 11:38:35 PM UTC
Silent Installation of Tor Browser
User labuser executes tor-browser-windows-x86_64-portable-14.5.2.exe with the /S flag (silent install).


This runs without UI interaction, installing the portable Tor Browser quietly in the background.


SHA256 hash of the file:
 3d55deb5dc8f0dc7fb694608ea15d255078e1087174d49d9a8fff6dc3f16b7ec



🕓 11:39:03 PM UTC
Tor Browser Launched
Processes firefox.exe and tor.exe are executed, confirming that the Tor Browser was opened by labuser.


This indicates user intent to run the browser shortly after installation.



🕓 11:39:13 PM UTC
Connection to Tor Network Established
A successful network connection from tor.exe is made to remote IP 37.48.90.84 over port 9001, a known Tor relay port.


Confirms active use of the Tor network to anonymize traffic.


Other outbound connections over port 443 are also observed, indicating browsing activity.



🕓 11:52:05 PM UTC
Suspicious File Created: "tor-shopping-list"
A file named "tor-shopping-list" appears on the Desktop.


This file may contain user intentions, plans, or other content related to their use of Tor, and warrants further review.

---

## Summary

The user "labuser" on the "trey-final-thre" device initiated and completed the installation of the TOR browser. They proceeded to launch the browser, establish connections within the TOR network, and created various files related to TOR on their desktop, including a file named `tor-shopping-list.txt`. This sequence of activities indicates that the user actively installed, configured, and used the TOR browser, likely for anonymous browsing purposes, with possible documentation in the form of the "shopping list" file.

---

## Response Taken

TOR usage was confirmed on the endpoint `trey-final-thre` by the user `labuser`. The device was isolated, and the user's direct manager was notified.

---
