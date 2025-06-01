// Define multiple quizzes
const quizzes = {
    "Cybersecurity Easy": {
        questions: [
            {
                "question": "What does the CIA Triad stand for?",
                "options": ["Confidentiality, Integrity, Availability", "Confidentiality, Integrity, Authentication", "Confidentiality, Integrity, Accountability", "Confidentiality, Integrity, Authorization"],
                "correctAnswer": 0,
                "category": "General Security Concepts"
            },
            {
                "question": "Which of the following is NOT a principle of the Zero Trust Model?",
                "options": ["Trust but verify", "Assume breach", "Least privilege", "Micro-segmentation"],
                "correctAnswer": 0,
                "category": "General Security Concepts"
            },
            {
                "question": "What is the purpose of non-repudiation in security?",
                "options": ["To ensure data is not altered", "To ensure users cannot deny their actions", "To ensure data is available when needed", "To ensure data is encrypted"],
                "correctAnswer": 1,
                "category": "General Security Concepts"
            },
            {
                "question": "Which of the following is an example of a technical security control?",
                "options": ["Security awareness training", "Access control policy", "Firewall", "Security audit"],
                "correctAnswer": 2,
                "category": "General Security Concepts"
            },
            {
                "question": "What is the primary goal of data classification?",
                "options": ["To ensure data is encrypted", "To determine the level of protection required", "To delete unnecessary data", "To store data in the cloud"],
                "correctAnswer": 1,
                "category": "General Security Concepts"
            },
            {
                "question": "Which of the following is a type of security control that discourages potential attackers?",
                "options": ["Preventive", "Deterrent", "Detective", "Corrective"],
                "correctAnswer": 1,
                "category": "General Security Concepts"
            },
            {
                "question": "What is the difference between authentication and authorization?",
                "options": ["Authentication verifies identity, while authorization determines access rights", "Authorization verifies identity, while authentication determines access rights", "Authentication and authorization are the same thing", "Authentication is a type of authorization"],
                "correctAnswer": 0,
                "category": "General Security Concepts"
            },
            {
                "question": "Which of the following is an example of a physical security control?",
                "options": ["Encryption", "Access badges", "Firewall", "Intrusion detection system"],
                "correctAnswer": 1,
                "category": "General Security Concepts"
            },
            {
                "question": "What is the purpose of a security information and event management (SIEM) system?",
                "options": ["To encrypt data", "To monitor and analyze security events", "To provide physical security", "To manage user accounts"],
                "correctAnswer": 1,
                "category": "General Security Concepts"
            },
            {
                "question": "Which of the following is a type of security control that corrects or remediates a security incident?",
                "options": ["Preventive", "Detective", "Corrective", "Compensating"],
                "correctAnswer": 2,
                "category": "General Security Concepts"
            },
            {
                "question": "What is the purpose of the principle of least privilege?",
                "options": ["To grant users maximum access to resources", "To grant users only the access they need to perform their job", "To grant users access based on their seniority", "To grant users access based on their department"],
                "correctAnswer": 1,
                "category": "General Security Concepts"
            },
            {
                "question": "Which of the following is an example of a security control that detects malicious activity?",
                "options": ["Firewall", "Intrusion detection system", "Encryption", "Access control policy"],
                "correctAnswer": 1,
                "category": "General Security Concepts"
            },
            {
                "question": "What is a zero-day vulnerability?",
                "options": ["A vulnerability that has been patched", "A vulnerability that is known to the vendor but not yet patched", "A vulnerability that is unknown to the vendor", "A vulnerability that is known to the public"],
                "correctAnswer": 2,
                "category": "Threats, Vulnerabilities, and Mitigations"
            },
            {
                "question": "Which of the following is an example of a threat actor motivated by financial gain?",
                "options": ["Hacktivist", "Nation-state actor", "Organized crime", "Insider threat"],
                "correctAnswer": 2,
                "category": "Threats, Vulnerabilities, and Mitigations"
            },
            {
                "question": "What is the difference between a threat and a vulnerability?",
                "options": ["A threat is a weakness, while a vulnerability is a potential danger", "A threat is a potential danger, while a vulnerability is a weakness", "A threat and a vulnerability are the same thing", "A threat is a risk, while a vulnerability is a threat"],
                "correctAnswer": 1,
                "category": "Threats, Vulnerabilities, and Mitigations"
            },
            {
                "question": "Which of the following is an example of a threat vector?",
                "options": ["Unpatched software", "Phishing email", "Malware", "Social engineering"],
                "correctAnswer": 1,
                "category": "Threats, Vulnerabilities, and Mitigations"
            },
            {
                "question": "What is the purpose of a honeypot?",
                "options": ["To prevent attacks", "To detect and analyze attacks", "To encrypt data", "To provide access control"],
                "correctAnswer": 1,
                "category": "Threats, Vulnerabilities, and Mitigations"
            },
            {
                "question": "Which of the following is an example of a vulnerability in a web application?",
                "options": ["SQL injection", "DDoS attack", "Malware infection", "Social engineering"],
                "correctAnswer": 0,
                "category": "Threats, Vulnerabilities, and Mitigations"
            },
            {
                "question": "What is the purpose of a security audit?",
                "options": ["To encrypt data", "To detect vulnerabilities", "To provide access control", "To monitor network traffic"],
                "correctAnswer": 1,
                "category": "Threats, Vulnerabilities, and Mitigations"
            },
            {
                "question": "Which of the following is an example of a threat actor motivated by philosophical or political beliefs?",
                "options": ["Hacktivist", "Nation-state actor", "Organized crime", "Insider threat"],
                "correctAnswer": 0,
                "category": "Threats, Vulnerabilities, and Mitigations"
            },
            {
                "question": "What is the purpose of a security control?",
                "options": ["To provide access to resources", "To protect assets from threats", "To encrypt data", "To monitor network traffic"],
                "correctAnswer": 1,
                "category": "Threats, Vulnerabilities, and Mitigations"
            },
            {
                "question": "What is the purpose of a security incident response plan?",
                "options": ["To prevent security incidents", "To detect and respond to security incidents", "To encrypt data", "To provide access control"],
                "correctAnswer": 1,
                "category": "Security Operations"
            },
            {
                "question": "Which of the following is a phase of the incident response process?",
                "options": ["Preparation", "Detection", "Containment", "All of the above"],
                "correctAnswer": 3,
                "category": "Security Operations"
            },
            {
                "question": "What is the purpose of threat hunting?",
                "options": ["To detect threats that have not been discovered by normal security monitoring", "To prevent security incidents", "To encrypt data", "To provide access control"],
                "correctAnswer": 0,
                "category": "Security Operations"
            },
            {
                "question": "Which of the following is a step in the root cause analysis process?",
                "options": ["Define and scope the incident", "Determine causal relationships", "Identify effective solutions", "All of the above"],
                "correctAnswer": 3,
                "category": "Security Operations"
            },
            {
                "question": "What is the purpose of digital forensic procedures?",
                "options": ["To investigate cybercrimes or security incidents", "To gather, analyze, and preserve digital evidence", "To provide legal evidence", "All of the above"],
                "correctAnswer": 3,
                "category": "Security Operations"
            },
            {
                "question": "Which of the following is a phase of the digital forensic process?",
                "options": ["Identification", "Collection", "Analysis", "All of the above"],
                "correctAnswer": 3,
                "category": "Security Operations"
            },
            {
                "question": "What is the purpose of data collection procedures?",
                "options": ["To gather relevant information during incident response", "To preserve evidence", "To ensure data is not lost or modified", "All of the above"],
                "correctAnswer": 3,
                "category": "Security Operations"
            },
            {
                "question": "Which of the following is an example of a data source for incident investigation?",
                "options": ["Vulnerability scans", "Packet captures", "Logs", "All of the above"],
                "correctAnswer": 3,
                "category": "Security Operations"
            },
            {
                "question": "What is the purpose of a SIEM system?",
                "options": ["To provide real-time analysis of security alerts", "To correlate and analyze log data", "To generate alerts for security teams", "All of the above"],
                "correctAnswer": 3,
                "category": "Security Operations"
            },
            {
                "question": "Which of the following is an example of a network traffic analysis tool?",
                "options": ["NetFlow", "Zeek", "MRTG", "All of the above"],
                "correctAnswer": 3,
                "category": "Security Operations"
            },
            {
                "question": "What is the purpose of a single pane of glass (SPOG)?",
                "options": ["To provide a central point of access for security teams", "To provide a unified view of the security posture", "To facilitate informed decision-making", "All of the above"],
                "correctAnswer": 3,
                "category": "Security Operations"
            },
            {
                "question": "Which of the following is a benefit of automation and orchestration?",
                "options": ["Increased efficiency and time savings", "Enforcement of baselines", "Secure scaling", "All of the above"],
                "correctAnswer": 3,
                "category": "Security Operations"
            },
            {
                "question": "What is the purpose of a playbook in security automation?",
                "options": ["To guide incident response processes", "To execute automated tasks with human decision points", "To automate support ticket management", "To automate application development"],
                "correctAnswer": 0,
                "category": "Security Operations"
            },
            {
                "question": "Which of the following is a benefit of automating onboarding processes?",
                "options": ["Eliminates manual tasks", "Reduces errors", "Provides structured, consistent onboarding", "All of the above"],
                "correctAnswer": 3,
                "category": "Security Operations"
            },
            {
                "question": "What is the purpose of automating security?",
                "options": ["To prevent security vulnerabilities", "To respond to threats swiftly", "To maintain consistent security policies", "All of the above"],
                "correctAnswer": 3,
                "category": "Security Operations"
            },
            {
                "question": "Which of the following is an example of a security automation task?",
                "options": ["Implementing guardrails", "Managing security groups", "Enabling and disabling services and access", "All of the above"],
                "correctAnswer": 3,
                "category": "Security Operations"
            },
            {
                "question": "What is the purpose of a security awareness program?",
                "options": ["To equip individuals to recognize and respond to threats", "To provide data protection", "To educate employees on security threats and mitigation measures", "All of the above"],
                "correctAnswer": 3,
                "category": "Security Program Management and Oversight"
            },
            {
                "question": "Which of the following is an example of an insider threat indicator?",
                "options": ["Emotional distress", "Lifestyle incongruences", "Financial struggles", "All of the above"],
                "correctAnswer": 3,
                "category": "Security Program Management and Oversight"
            },
            {
                "question": "What is the purpose of a password manager?",
                "options": ["To securely store and manage passwords", "To prevent password reuse", "To simplify password management", "All of the above"],
                "correctAnswer": 3,
                "category": "Security Program Management and Oversight"
            },
            {
                "question": "Which of the following is a security challenge associated with remote work?",
                "options": ["Increased risk due to lack of physical security controls", "Data transmitted over public and private networks", "Weak security controls on home and public networks", "All of the above"],
                "correctAnswer": 3,
                "category": "Security Program Management and Oversight"
            },
            {
                "question": "What is the purpose of a security policy?",
                "options": ["To provide a system of principles and rules guiding decisions", "To ensure compliance with legal and ethical standards", "To provide guidance on handling various situations", "All of the above"],
                "correctAnswer": 3,
                "category": "Security Program Management and Oversight"
            },
            {
                "question": "Which of the following is an example of a policy that might be included in a handbook?",
                "options": ["Data destruction policy", "Remote work policy", "Data protection policy", "All of the above"],
                "correctAnswer": 3,
                "category": "Security Program Management and Oversight"
            },
            {
                "question": "What is the purpose of a data classification policy?",
                "options": ["To determine the level of protection required for data", "To ensure data is encrypted", "To delete unnecessary data", "To store data in the cloud"],
                "correctAnswer": 0,
                "category": "Security Program Management and Oversight"
            },
            {
                "question": "Which of the following is an example of a security program management activity?",
                "options": ["Security awareness training", "Risk management", "Compliance management", "All of the above"],
                "correctAnswer": 3,
                "category": "Security Program Management and Oversight"
            },
            {
                "question": "What is the purpose of a security program?",
                "options": ["To provide a framework for managing security risks", "To ensure the confidentiality, integrity, and availability of information assets", "To align security with business objectives", "All of the above"],
                "correctAnswer": 3,
                "category": "Security Program Management and Oversight"
            },
            {
                "question": "Which of the following is a security governance structure?",
                "options": ["Boards and committees", "Government entities", "Centralized and decentralized structures", "All of the above"],
                "correctAnswer": 3,
                "category": "Security Program Management and Oversight"
            },
            {
                "question": "What is the purpose of a compliance program?",
                "options": ["To ensure adherence to laws, regulations, standards, and policies", "To prevent breaches and protect privacy", "To ensure business continuity", "All of the above"],
                "correctAnswer": 3,
                "category": "Security Program Management and Oversight"
            },
            {
                "question": "Which of the following is an example of a compliance reporting type?",
                "options": ["Internal compliance reporting", "External compliance reporting", "Both A and B", "Neither A nor B"],
                "correctAnswer": 2,
                "category": "Security Program Management and Oversight"
            },
            {
                "question": "What is the purpose of a risk management program?",
                "options": ["To identify, assess, and manage potential risks", "To align IT strategy with business objectives", "To ensure efficient and effective use of IT resources", "All of the above"],
                "correctAnswer": 0,
                "category": "Security Program Management and Oversight"
            },
            {
                "question": "Which of the following is a risk management strategy?",
                "options": ["Risk transfer", "Risk acceptance", "Risk avoidance", "All of the above"],
                "correctAnswer": 3,
                "category": "Security Program Management and Oversight"
            },
            {
                "question": "What is the purpose of a third-party vendor risk assessment?",
                "options": ["To evaluate the security, reliability, and performance of external entities", "To ensure interconnectivity and potential impact on multiple businesses", "To assess the security of vendors, suppliers, or service providers", "All of the above"],
                "correctAnswer": 3,
                "category": "Security Program Management and Oversight"
            },
            {
                "question": "Which of the following is an example of a supply chain risk?",
                "options": ["Hardware manufacturers", "Secondary/aftermarket sources", "Software developers/providers", "All of the above"],
                "correctAnswer": 3,
                "category": "Security Program Management and Oversight"
            },
            {
                "question": "What is the purpose of a vendor assessment?",
                "options": ["To evaluate the security, reliability, and performance of vendors", "To ensure compliance with security standards", "To assess the risk of vendor relationships", "All of the above"],
                "correctAnswer": 3,
                "category": "Security Program Management and Oversight"
            },
            {
                "question": "Which of the following is a type of contract or agreement?",
                "options": ["Service Level Agreement (SLA)", "Memorandum of Agreement (MOA)", "Non-Disclosure Agreement (NDA)", "All of the above"],
                "correctAnswer": 3,
                "category": "Security Program Management and Oversight"
            }
        ],
        icon: "fa-user-shield",
        color: "cybersecurity",
        difficulty: "Easy",
        participants: 36,
        description: "Test your knowledge of basic cybersecurity concepts."
    },
    "Cybersecurity Medium": {
        questions: [
            {
                "question": "A security administrator is designing a network segmentation strategy and wants to ensure that only authenticated devices can communicate with critical servers. Which control should be implemented to verify device health before granting network access?",
                "options": [
                    "802.1X with RADIUS authentication",
                    "MAC address filtering",
                    "Network Access Control (NAC)",
                    "Port Security"
                ],
                "correctAnswer": 2,
                "category": "General Security Concepts"
            },
            {
                "question": "An organization needs to ensure data confidentiality when transmitting sensitive financial reports between branch offices over the public Internet. Which of the following solutions provides the strongest encryption for this purpose?",
                "options": [
                    "IPsec in tunnel mode",
                    "SSL/TLS VPN",
                    "SSH tunnel",
                    "WEP encryption"
                ],
                "correctAnswer": 0,
                "category": "General Security Concepts"
            },
            {
                "question": "A help desk technician receives a report that a user’s account has been locked out after multiple failed login attempts. The technician suspects a brute-force attack. Which of the following preventive controls would best mitigate this risk?",
                "options": [
                    "Account lockout threshold and cooldown",
                    "Installing a host-based firewall",
                    "Deploying an IDS sensor",
                    "Implementing least privilege"
                ],
                "correctAnswer": 0,
                "category": "General Security Concepts"
            },
            {
                "question": "A security architect is comparing integrity solutions. Which of the following uses a one-way mathematical function to ensure data has not been altered?",
                "options": [
                    "Digital signatures",
                    "Hashing",
                    "Symmetric encryption",
                    "Salting"
                ],
                "correctAnswer": 1,
                "category": "General Security Concepts"
            },
            {
                "question": "A company wants to verify that employees cannot deny sending critical documents. Which principle of the CIA triad addresses this requirement?",
                "options": [
                    "Integrity",
                    "Availability",
                    "Non-repudiation",
                    "Authentication"
                ],
                "correctAnswer": 2,
                "category": "General Security Concepts"
            },
            {
                "question": "An organization is implementing multi-factor authentication (MFA) for remote access. The second factor is a one-time password delivered via SMS. Which factor categories are employed in this MFA implementation?",
                "options": [
                    "Something you know and something you have",
                    "Something you are and something you know",
                    "Something you have and something you are",
                    "Something you know and something you do"
                ],
                "correctAnswer": 0,
                "category": "General Security Concepts"
            },
            {
                "question": "A security team wants to reduce the attack surface of a legacy web application. Which of the following is the MOST effective mitigation?",
                "options": [
                    "Implement a web application firewall (WAF)",
                    "Disable unused services and ports on the web server",
                    "Perform quarterly vulnerability scans",
                    "Rotate application encryption keys weekly"
                ],
                "correctAnswer": 1,
                "category": "General Security Concepts"
            },
            {
                "question": "A systems administrator configures a critical financial database to replicate to a secondary site every 10 minutes and uses RAID 1 on each server. Which aspect of CIA is this control primarily addressing?",
                "options": [
                    "Confidentiality",
                    "Integrity",
                    "Availability",
                    "Non-repudiation"
                ],
                "correctAnswer": 2,
                "category": "General Security Concepts"
            },
            {
                "question": "A penetration tester is tasked with bypassing perimeter defenses by exploiting a user’s trust. Which of the following social engineering techniques is the tester MOST likely to attempt first?",
                "options": [
                    "Phishing email with a malicious attachment",
                    "Shoulder surfing at the target’s desk",
                    "Dumpster diving for discarded credentials",
                    "Smishing via text message"
                ],
                "correctAnswer": 0,
                "category": "General Security Concepts"
            },
            {
                "question": "A security policy states that all passwords must be changed every 90 days and must not be reused. Which type of control is this policy?",
                "options": [
                    "Technical control",
                    "Administrative control",
                    "Physical control",
                    "Compensating control"
                ],
                "correctAnswer": 1,
                "category": "General Security Concepts"
            },
            {
                "question": "An organization deploying a zero trust model wants to ensure each resource request is evaluated individually. Which of the following components enforces policies at each control point?",
                "options": [
                    "Policy Engine",
                    "Policy Administrator",
                    "Policy Enforcement Point (PEP)",
                    "Data Plane"
                ],
                "correctAnswer": 2,
                "category": "General Security Concepts"
            },
            {
                "question": "A network engineer wants to ensure confidentiality of data at rest on mobile devices. Which control should be deployed?",
                "options": [
                    "Full-disk encryption",
                    "Secure boot",
                    "Trusted Platform Module (TPM)",
                    "Endpoint DLP"
                ],
                "correctAnswer": 0,
                "category": "General Security Concepts"
            },
            {
                "question": "A new employee at a high-security facility must pass through two sets of doors and present a valid badge at each checkpoint. If the first door is still open, the second door remains locked until the first door closes. Which physical security mechanism is this?",
                "options": [
                    "Mantrap",
                    "Turnstile",
                    "Tailgating detector",
                    "Bollard"
                ],
                "correctAnswer": 0,
                "category": "Physical Security"
            },
            {
                "question": "A data center manager wants to detect if someone tries to unscrew cameras or cut cable connections. Which physical security control should be implemented?",
                "options": [
                    "Pressure sensors around camera mounts",
                    "Honeytokens in camera logs",
                    "Access control vestibule",
                    "Bollards around the data center"
                ],
                "correctAnswer": 0,
                "category": "Physical Security"
            },
            {
                "question": "A security guard notices that multiple motion sensors are triggering false alarms due to a HVAC unit flickering. Which of the following sensor types is LEAST likely to be affected by this issue?",
                "options": [
                    "Infrared sensor",
                    "Pressure sensor",
                    "Ultrasonic sensor",
                    "Microwave sensor"
                ],
                "correctAnswer": 1,
                "category": "Physical Security"
            },
            {
                "question": "A company wants to protect against tailgating into its server room. Which of the following is the BEST deterrent?",
                "options": [
                    "Security guards at the entrance",
                    "Door locks with numeric pads",
                    "Video surveillance alone",
                    "Installing bollards"
                ],
                "correctAnswer": 0,
                "category": "Physical Security"
            },
            {
                "question": "An attacker sprays paint over a security camera lens before entering a restricted area. Which method did the attacker use?",
                "options": [
                    "Visual obstruction",
                    "Electromagnetic interference",
                    "Tailgating",
                    "Shoulder surfing"
                ],
                "correctAnswer": 0,
                "category": "Physical Security"
            },
            {
                "question": "A facility manager is considering fencing and bollards around a sensitive building. Which of the following statements is TRUE?",
                "options": [
                    "Bollards are primarily used to prevent unauthorized foot traffic.",
                    "Fencing is effective against vehicular threats but not pedestrian threats.",
                    "Fencing provides a visual deterrent and delays intruders, while bollards prevent vehicle-based attacks.",
                    "Bollards are more adaptable than fencing for large perimeters."
                ],
                "correctAnswer": 2,
                "category": "Physical Security"
            },
            {
                "question": "A high-security vault door uses biometric fingerprint readers and PIN codes. Which of the following authentication factors are combined here?",
                "options": [
                    "Something you know and something you have",
                    "Something you know and something you are",
                    "Something you are and something you have",
                    "Something you do and something you have"
                ],
                "correctAnswer": 1,
                "category": "Physical Security"
            },
            {
                "question": "A CFO received an email appearing to come from the CEO requesting an urgent wire transfer. The email address matches the CEO’s domain but the language seems unusual. Which type of attack is this MOST likely?",
                "options": [
                    "Spear phishing",
                    "Whaling",
                    "Vishing",
                    "Business Email Compromise (BEC)"
                ],
                "correctAnswer": 3,
                "category": "Social Engineering"
            },
            {
                "question": "An employee checks a friend’s credibly urgent message to reset their password and clicks the link, revealing credentials to an attacker. Which motivational trigger did the attacker exploit?",
                "options": [
                    "Authority",
                    "Fear",
                    "Scarcity",
                    "Familiarity (Likability)"
                ],
                "correctAnswer": 3,
                "category": "Social Engineering"
            },
            {
                "question": "A security awareness instructor wants to simulate phishing training. Which control is MOST effective to teach users to identify malicious URLs in emails?",
                "options": [
                    "Anti-phishing software on email gateway",
                    "Regular phishing simulation campaigns with remedial training",
                    "Endpoint DLP to block unsafe attachments",
                    "Implementing DNS sinkholing"
                ],
                "correctAnswer": 1,
                "category": "Social Engineering"
            },
            {
                "question": "An attacker registers a domain name that differs from the company’s by one character and sets up a fake login page. Which type of attack is this?",
                "options": [
                    "Pharming",
                    "Typosquatting",
                    "Watering hole",
                    "Whaling"
                ],
                "correctAnswer": 1,
                "category": "Social Engineering"
            },
            {
                "question": "During an assessment, you discover a hidden folder named “C:\\Windows\\System32\\Drivers\\etc\\hosts.old” that contains malicious entries redirecting traffic. Which deception technology best mimics legitimate directories to detect intruders?",
                "options": [
                    "Honeynet",
                    "Honeytoken",
                    "Honeyfile",
                    "Honeypot"
                ],
                "correctAnswer": 2,
                "category": "Social Engineering"
            },
            {
                "question": "A user reports receiving suspicious phone calls asking for their login credentials, claiming to be from IT support. Which type of social engineering attack is this?",
                "options": [
                    "Pharming",
                    "Vishing",
                    "Smishing",
                    "Spear phishing"
                ],
                "correctAnswer": 1,
                "category": "Social Engineering"
            },
            {
                "question": "A malicious insider copies a database of proprietary product designs onto a USB flash drive left in a parking lot for an unwitting employee to find and plug into their workstation. Which attack vector is this?",
                "options": [
                    "Pretexting",
                    "Baiting",
                    "Tailgating",
                    "Brute force"
                ],
                "correctAnswer": 1,
                "category": "Social Engineering"
            },
            {
                "question": "During a penetration test, an attacker places a USB drive labeled “Executive Salaries” in the company lobby. An employee picks it up and plugs it into their workstation. What type of social engineering technique is this?",
                "options": [
                    "Phishing",
                    "Baiting",
                    "Shoulder surfing",
                    "Pretexting"
                ],
                "correctAnswer": 1,
                "category": "Social Engineering"
            },
            {
                "question": "A new employee hacks into the company’s printer to install a keystroke logger. Which malware category does this device-level exploit represent?",
                "options": [
                    "Rootkit",
                    "Spyware",
                    "Worm",
                    "Trojan horse"
                ],
                "correctAnswer": 1,
                "category": "Malware"
            },
            {
                "question": "A security analyst observes a significant increase in CPU usage on several servers, and network bandwidth is nearly saturated. The devices are communicating with unknown external IPs at high frequency. Which malware indicator does this describe?",
                "options": [
                    "Impossible travel",
                    "Resource consumption",
                    "Account lockouts",
                    "Out-of-cycle logging"
                ],
                "correctAnswer": 1,
                "category": "Malware"
            },
            {
                "question": "A user’s workstation suddenly displays a message that all files have been encrypted and demands payment in cryptocurrency within 48 hours. What type of malware is responsible?",
                "options": [
                    "Ransomware",
                    "Worm",
                    "Rootkit",
                    "Spyware"
                ],
                "correctAnswer": 0,
                "category": "Malware"
            },
            {
                "question": "An attacker uses an infected email attachment to drop a small shellcode on a user’s workstation, which then downloads additional payloads. Which term correctly describes the initial malicious code?",
                "options": [
                    "Exploit kit",
                    "Stage 1 dropper",
                    "Rootkit",
                    "Logic bomb"
                ],
                "correctAnswer": 1,
                "category": "Malware"
            },
            {
                "question": "A security engineer finds a hidden kernel module that hides files and processes, preventing antivirus from detecting them. Which type of malware is this MOST likely?",
                "options": [
                    "Backdoor",
                    "Polymorphic virus",
                    "Rootkit",
                    "Worm"
                ],
                "correctAnswer": 2,
                "category": "Malware"
            },
            {
                "question": "A compromised system is part of a network of machines controlled remotely, used to launch a distributed denial-of-service (DDoS) attack. What is this network of infected machines called?",
                "options": [
                    "Zombie army",
                    "Botnet",
                    "Rootkit cluster",
                    "Honeynet"
                ],
                "correctAnswer": 1,
                "category": "Malware"
            },
            {
                "question": "A USB-based hardware keylogger is discovered attached to a critical server console. Which of the following is the primary concern regarding this device?",
                "options": [
                    "Privilege escalation",
                    "Data exfiltration",
                    "Credential theft",
                    "Denial of service"
                ],
                "correctAnswer": 2,
                "category": "Malware"
            },
            {
                "question": "A company notices that the DNS entries for their banking portal have been altered to redirect users to a malicious site without changing the URL visible in the browser. Which type of attack is this?",
                "options": [
                    "Typosquatting",
                    "Whaling",
                    "Pharming",
                    "Man-in-the-middle"
                ],
                "correctAnswer": 2,
                "category": "Malware"
            },
            {
                "question": "A cybersecurity team wants to detect signs of a rootkit on a Linux server. Which of the following approaches is MOST effective?",
                "options": [
                    "Checking the output of ‘lsmod’ for unexpected kernel modules and comparing file hashes from a known-good source",
                    "Running a full scan with a user-mode antivirus software while the system is online",
                    "Reviewing user activity logs for abnormal login times",
                    "Monitoring CPU usage over time"
                ],
                "correctAnswer": 0,
                "category": "Malware"
            },
            {
                "question": "An attacker gains unauthorized access by sending a specially crafted packet to exploit a buffer overflow in a network service. Which type of attack technique is this?",
                "options": [
                    "Phishing",
                    "SQL injection",
                    "Exploit",
                    "Brute force"
                ],
                "correctAnswer": 2,
                "category": "Threats, Vulnerabilities, and Mitigations"
            },
            {
                "question": "A security analyst reviews a system log and notices multiple failed authentication attempts followed by a successful login from a new IP address. What type of vulnerability assessment tool could have detected this pattern earlier?",
                "options": [
                    "Web application scanner",
                    "Host-based intrusion detection system (HIDS)",
                    "Network vulnerability scanner",
                    "SNMP monitoring"
                ],
                "correctAnswer": 1,
                "category": "Threats, Vulnerabilities, and Mitigations"
            },
            {
                "question": "A threat actor uses a dropper to install a memory-resident payload that never writes to disk. Which mitigation strategy is MOST effective against this type of fileless malware?",
                "options": [
                    "Antivirus signature updates",
                    "Application whitelisting and behavioral monitoring",
                    "Port scanning",
                    "Regular patching of web servers"
                ],
                "correctAnswer": 1,
                "category": "Threats, Vulnerabilities, and Mitigations"
            },
            {
                "question": "A malicious actor crafts a SQL injection payload and injects it into a web application’s login page, retrieving user credentials from the database. Which principle of secure coding would prevent this vulnerability?",
                "options": [
                    "Input validation and parameterized queries",
                    "Using strong password policies",
                    "Implementing SSDLC",
                    "Encrypting data in transit"
                ],
                "correctAnswer": 0,
                "category": "Threats, Vulnerabilities, and Mitigations"
            },
            {
                "question": "A newly discovered zero-day vulnerability affects the SSL/TLS implementation of a popular web server. The vendor has not released a patch yet. Which of the following is the BEST compensating control to reduce risk until the patch is available?",
                "options": [
                    "Disable SSL/TLS entirely",
                    "Place the web server behind an up-to-date web application firewall (WAF)",
                    "Enforce longer password complexity requirements",
                    "Enable verbose logging on the server"
                ],
                "correctAnswer": 1,
                "category": "Threats, Vulnerabilities, and Mitigations"
            },
            {
                "question": "An organization’s security team wants to identify vulnerabilities resulting from misconfigurations and outdated software on internal assets. Which tool combination will yield the most comprehensive results?",
                "options": [
                    "Network vulnerability scanner and patch management system",
                    "Penetration testing and phishing simulations",
                    "Firewall configuration review only",
                    "Host-based antivirus and OS firewall"
                ],
                "correctAnswer": 0,
                "category": "Threats, Vulnerabilities, and Mitigations"
            },
            {
                "question": "A penetration test reveals that an internal web application is vulnerable to cross-site scripting (XSS). Which risk mitigation technique should be applied during development to prevent XSS attacks?",
                "options": [
                    "Encrypting cookies with AES-256",
                    "Encoding or escaping user-supplied output",
                    "Implementing account lockout thresholds",
                    "Disabling directory listing on the web server"
                ],
                "correctAnswer": 1,
                "category": "Threats, Vulnerabilities, and Mitigations"
            },
            {
                "question": "A threat actor attempts to overwhelm a critical web server by sending a flood of HTTP requests from multiple compromised hosts. Which attack is occurring?",
                "options": [
                    "SYN flood",
                    "ARP poisoning",
                    "Distributed Denial of Service (DDoS)",
                    "Man-in-the-middle"
                ],
                "correctAnswer": 2,
                "category": "Threats, Vulnerabilities, and Mitigations"
            },
            {
                "question": "A network administrator configures VLAN pruning to isolate sensitive financial servers from the main VLAN. Which attack vector is this measure MOST effective against?",
                "options": [
                    "ARP spoofing",
                    "VLAN hopping",
                    "MAC flooding",
                    "DNS cache poisoning"
                ],
                "correctAnswer": 1,
                "category": "Threats, Vulnerabilities, and Mitigations"
            },
            {
                "question": "An attacker uses a phishing email to lure an employee to a malicious website hosting an exploit kit. Which part of the kill chain does this represent?",
                "options": [
                    "Delivery",
                    "Weaponization",
                    "Installation",
                    "Command and Control"
                ],
                "correctAnswer": 0,
                "category": "Threats, Vulnerabilities, and Mitigations"
            },
            {
                "question": "A developer implements Content Security Policy (CSP) headers in a web application. Which vulnerability class does CSP chiefly mitigate?",
                "options": [
                    "SQL injection",
                    "Cross-site scripting (XSS)",
                    "Buffer overflow",
                    "Broken authentication"
                ],
                "correctAnswer": 1,
                "category": "Threats, Vulnerabilities, and Mitigations"
            },
            {
                "question": "During a security assessment, a vulnerability scan shows the SMB service on an outdated Windows server is exposed directly to the Internet. Which immediate action will MOST likely reduce risk?",
                "options": [
                    "Enable SMB signing",
                    "Block SMB (TCP port 445) at the perimeter firewall",
                    "Upgrade SMB to the latest version",
                    "Disable guest account"
                ],
                "correctAnswer": 1,
                "category": "Threats, Vulnerabilities, and Mitigations"
            },
            {
                "question": "A security engineer discovers that an application stores sensitive user data in plaintext on the server. Which of the following best addresses this vulnerability?",
                "options": [
                    "Encrypt data at rest using AES-256",
                    "Implement account lockout",
                    "Use TLS for data in transit",
                    "Enable application sandboxing"
                ],
                "correctAnswer": 0,
                "category": "Threats, Vulnerabilities, and Mitigations"
            },
            {
                "question": "A server compromised by a malicious actor is flooding DNS requests with spoofed source IP addresses, causing service degradation. Which attack is this?",
                "options": [
                    "DNS amplification",
                    "ARP spoofing",
                    "Man-in-the-middle",
                    "Replay attack"
                ],
                "correctAnswer": 0,
                "category": "Threats, Vulnerabilities, and Mitigations"
            },
            {
                "question": "An administrator uses DevSecOps practices and implements automated scanning for known vulnerabilities in code before deployment. Which phase of the software development lifecycle does this best exemplify?",
                "options": [
                    "Testing",
                    "Deployment",
                    "Maintenance",
                    "Requirements gathering"
                ],
                "correctAnswer": 0,
                "category": "Security Architecture"
            },
            {
                "question": "A company plans to host its public-facing web application in a cloud environment. Which architectural control should be put in place to segment network traffic between application tiers?",
                "options": [
                    "Virtual LAN (VLAN)",
                    "Security groups",
                    "User-based ACL",
                    "MAC filtering"
                ],
                "correctAnswer": 1,
                "category": "Security Architecture"
            },
            {
                "question": "A security architect is designing a distributed application that must remain available even if one data center is lost. Which architecture pattern should be used?",
                "options": [
                    "Active-passive clustering",
                    "Single point of failure architecture",
                    "Geographic redundancy with load balancing",
                    "Monolithic deployment"
                ],
                "correctAnswer": 2,
                "category": "Security Architecture"
            },
            {
                "question": "A company wants to implement secure remote access for employees working from various locations. Which combination of solutions provides encryption, authentication, and endpoint health checks?",
                "options": [
                    "SSL VPN with multifactor authentication",
                    "IPsec VPN with public key infrastructure (PKI)",
                    "Remote Desktop Protocol (RDP) over the open Internet",
                    "Port forwarding on the corporate firewall"
                ],
                "correctAnswer": 1,
                "category": "Security Architecture"
            },
            {
                "question": "A security team is designing an enterprise network and wants to place an intrusion prevention system (IPS) inline to actively block malicious traffic. Where should the IPS be placed?",
                "options": [
                    "On a monitoring port of a switch",
                    "Connected to a span port for passive monitoring",
                    "Between the Internet router and the firewall",
                    "Inside the server DMZ behind the web servers"
                ],
                "correctAnswer": 2,
                "category": "Security Architecture"
            },
            {
                "question": "A web application requires user credentials to be stored for authentication. Which design ensures the password is protected even if the database is compromised?",
                "options": [
                    "Store passwords using MD5 hashing without salt",
                    "Store passwords using bcrypt with a unique salt per user",
                    "Store passwords in plaintext but in a restricted directory",
                    "Store passwords using reversible encryption"
                ],
                "correctAnswer": 1,
                "category": "Security Architecture"
            },
            {
                "question": "An architect is evaluating a new load balancer for a high-availability web service. Which feature is MOST critical to ensure session persistence for end users?",
                "options": [
                    "SSL offloading",
                    "Sticky sessions (session affinity)",
                    "Layer 2 bridging",
                    "MAC address cloning"
                ],
                "correctAnswer": 1,
                "category": "Security Architecture"
            },
            {
                "question": "A security administrator wants to enable secure management of network devices without exposing cleartext credentials. Which protocol should be used?",
                "options": [
                    "FTP",
                    "Telnet",
                    "SSH",
                    "SNMPv1"
                ],
                "correctAnswer": 2,
                "category": "Security Architecture"
            },
            {
                "question": "During an architecture review, a network diagram shows that the database servers are directly accessible from the Internet. Which architectural violation is this?",
                "options": [
                    "Lack of tiered network segmentation",
                    "Excessive redundancy",
                    "Overprovisioning of resources",
                    "Use of NAT"
                ],
                "correctAnswer": 0,
                "category": "Security Architecture"
            },
            {
                "question": "A company wants to implement microsegmentation in its virtual environment. Which of the following concepts BEST describes this approach?",
                "options": [
                    "Firewall at the network perimeter only",
                    "Host-based firewall and access control for each VM",
                    "VLAN-based segmentation across all hosts",
                    "Switchport security with MAC filtering"
                ],
                "correctAnswer": 1,
                "category": "Security Architecture"
            },
            {
                "question": "A security architect is comparing TLS cipher suites. Which characteristic indicates a strong cipher suite?",
                "options": [
                    "Use of MD5 for message digest",
                    "RSA key exchange",
                    "Use of AES-GCM with 256-bit keys and ECDHE for key exchange",
                    "No forward secrecy"
                ],
                "correctAnswer": 2,
                "category": "Security Architecture"
            },
            {
                "question": "A development team wants to avoid proprietary vendor lock-in and ensure the application can run on any public or private cloud. Which architectural principle should they follow?",
                "options": [
                    "Monolithic architecture with custom APIs",
                    "Use of platform-as-a-service (PaaS) only",
                    "Build using containerization (e.g., Docker) and orchestration (e.g., Kubernetes)",
                    "Rely solely on serverless functions in one cloud provider"
                ],
                "correctAnswer": 2,
                "category": "Security Architecture"
            },
            {
                "question": "A security engineer needs to secure communications between microservices in a zero trust environment. Which mechanism would BEST meet this requirement?",
                "options": [
                    "TLS mutual authentication between each service",
                    "Rely on the perimeter firewall to block unauthorized traffic",
                    "Use HTTP with Basic Authentication",
                    "SSH tunneling for each service call"
                ],
                "correctAnswer": 0,
                "category": "Security Architecture"
            },
            {
                "question": "A risk assessment reveals an absence of network segmentation for critical assets. Which architectural control should be implemented first to reduce lateral movement risk?",
                "options": [
                    "Host-based antivirus on endpoints",
                    "Firewall rules between critical and non-critical VLANs",
                    "Disabling IPv6 on all devices",
                    "Turning off ICMP on the network"
                ],
                "correctAnswer": 1,
                "category": "Security Architecture"
            },
            {
                "question": "An enterprise has legacy IoT devices that only support outdated TLS 1.0. Which mitigation should the architect apply to secure traffic from these devices while minimizing exposure?",
                "options": [
                    "Replace all IoT devices immediately",
                    "Deploy a TLS proxy that translates TLS 1.0 to TLS 1.3",
                    "Disable TLS on other network devices",
                    "Use IPsec on the WAN only"
                ],
                "correctAnswer": 1,
                "category": "Security Architecture"
            },
            {
                "question": "A security architect is designing an SDN (Software-Defined Networking) environment. Which control plane component is responsible for making policy decisions?",
                "options": [
                    "Policy Enforcement Point",
                    "Data Plane switch",
                    "Policy Engine",
                    "Hypervisor"
                ],
                "correctAnswer": 2,
                "category": "Security Architecture"
            },
            {
                "question": "A cloud provider offers ephemeral storage for virtual machines. Which characteristic of ephemeral storage should be considered when designing the environment?",
                "options": [
                    "Data persists after VM termination",
                    "Data is automatically backed up to object storage",
                    "Data is lost when the VM is stopped or terminated",
                    "Data encryption is not supported"
                ],
                "correctAnswer": 2,
                "category": "Security Architecture"
            },
            {
                "question": "A security operations center (SOC) analyst receives an alert from the SIEM indicating multiple failed RDP login attempts followed by a successful login from an external IP. What type of attack BEST fits this scenario?",
                "options": [
                    "Brute force",
                    "Phishing",
                    "Watering hole",
                    "DDoS"
                ],
                "correctAnswer": 0,
                "category": "Security Operations"
            },
            {
                "question": "During a cybersecurity incident, a malicious file was identified on a Windows server. Which of the following is the MOST appropriate next step to collect forensic evidence while minimizing evidence tampering?",
                "options": [
                    "Reboot the server into Safe Mode and run a full antivirus scan",
                    "Pull the network cable and create a bit-for-bit image of the disk",
                    "Delete the malicious file to prevent further spread",
                    "Run ‘chkdsk’ to repair file system errors"
                ],
                "correctAnswer": 1,
                "category": "Security Operations"
            },
            {
                "question": "A help desk receives an alert that a user’s credentials may have been compromised. Which security operations process should be initiated to confirm and contain the incident?",
                "options": [
                    "Incident response playbook for account compromise",
                    "Disaster recovery plan",
                    "Business continuity plan",
                    "Penetration testing schedule"
                ],
                "correctAnswer": 0,
                "category": "Security Operations"
            },
            {
                "question": "A SOC team wants to centralize logs from servers, network devices, and applications for correlation. Which solution provides real-time aggregation, normalization, and alerting?",
                "options": [
                    "SIEM (Security Information and Event Management)",
                    "Vulnerability scanner",
                    "Endpoint protection platform",
                    "Web application firewall"
                ],
                "correctAnswer": 0,
                "category": "Security Operations"
            },
            {
                "question": "A server reports unusually high outbound traffic at odd hours. The security team suspects a data exfiltration. Which tool or technique would MOST effectively confirm this suspicion?",
                "options": [
                    "SSH login audit logs",
                    "Network flow analysis (NetFlow/sFlow)",
                    "Disk defragmentation analysis",
                    "VLAN tagging"
                ],
                "correctAnswer": 1,
                "category": "Security Operations"
            },
            {
                "question": "A security engineer notices that a web server’s SSL certificate is about to expire in two days. Which operation should be performed to maintain secure communications?",
                "options": [
                    "Rotate the encryption key on the database",
                    "Renew or replace the SSL/TLS certificate before expiration",
                    "Disable TLS on the web server",
                    "Enable HTTP only mode"
                ],
                "correctAnswer": 1,
                "category": "Security Operations"
            },
            {
                "question": "A company’s endpoint detection and response (EDR) solution blocks a suspicious process on a user’s workstation. The workstation still shows unusual behavior. What is the MOST appropriate next step?",
                "options": [
                    "Reboot the workstation immediately",
                    "Isolate the workstation from the network and perform a forensic analysis",
                    "Send a warning email to the user",
                    "Uninstall the EDR agent and reinstall it"
                ],
                "correctAnswer": 1,
                "category": "Security Operations"
            },
            {
                "question": "An attack on a critical application has been detected. The security team decides to perform threat hunting. Which activity is MOST likely part of the threat hunting process?",
                "options": [
                    "Applying the latest software patches",
                    "Proactively searching for indicators of compromise (IOCs) not flagged by automated tools",
                    "Restoring systems from backups",
                    "Configuring firewall rules"
                ],
                "correctAnswer": 1,
                "category": "Security Operations"
            },
            {
                "question": "A DDoS mitigation service is deployed to protect an online storefront. Which of the following metrics BEST indicates that the mitigation service is successfully filtering malicious traffic?",
                "options": [
                    "Increased CPU usage on the storefront server",
                    "Reduced inbound traffic to the storefront server from known malicious IPs",
                    "Higher memory utilization on the DDoS service appliance",
                    "Constant number of SSL handshakes"
                ],
                "correctAnswer": 1,
                "category": "Security Operations"
            },
            {
                "question": "A security operations team is reviewing alerts from a newly deployed IDS. They notice many false positives for port scans from known safe sources. Which action should they take to reduce noise?",
                "options": [
                    "Increase the sensitivity of the IDS",
                    "Add the safe sources’ IP addresses to an allowlist in the IDS",
                    "Disable IDS logging",
                    "Uninstall the IDS sensor"
                ],
                "correctAnswer": 1,
                "category": "Security Operations"
            },
            {
                "question": "A server’s antivirus logs show a quarantined file, but the SOC team wants to ensure no related files remain. Which tool is MOST appropriate for this task?",
                "options": [
                    "Port scanner",
                    "File integrity monitoring (FIM)",
                    "Network vulnerability scanner",
                    "Configuration management database (CMDB)"
                ],
                "correctAnswer": 1,
                "category": "Security Operations"
            },
            {
                "question": "A security analyst finds that logs from a critical application are not being ingested by the SIEM. Which step should be performed FIRST to troubleshoot?",
                "options": [
                    "Verify that the log forwarding agent on the application server is running and configured correctly",
                    "Reboot the SIEM appliance",
                    "Disable encryption on the log transport",
                    "Apply a new log parsing rule to the SIEM"
                ],
                "correctAnswer": 0,
                "category": "Security Operations"
            },
            {
                "question": "During a forensic analysis, the team needs to preserve a Windows system’s volatile memory. Which tool should be used to capture a memory image before powering off the machine?",
                "options": [
                    "Disk2vhd",
                    "FTK Imager or DumpIt",
                    "chkdsk",
                    "antimalware scan"
                ],
                "correctAnswer": 1,
                "category": "Security Operations"
            },
            {
                "question": "A new security policy requires that all application developers rotate API keys every 30 days. Which type of control does this represent?",
                "options": [
                    "Technical control",
                    "Administrative control",
                    "Physical control",
                    "Deterrent control"
                ],
                "correctAnswer": 1,
                "category": "Security Program Management and Oversight"
            },
            {
                "question": "A Chief Information Security Officer (CISO) is asked to estimate the likelihood and impact of a ransomware incident for the upcoming fiscal year. Which risk management process should be conducted?",
                "options": [
                    "Business impact analysis (BIA)",
                    "Gap analysis",
                    "Threat modeling",
                    "Security awareness training"
                ],
                "correctAnswer": 0,
                "category": "Security Program Management and Oversight"
            },
            {
                "question": "An organization must comply with GDPR regarding user data protection. Which of the following is MOST important to include in the security program?",
                "options": [
                    "Regular penetration testing only",
                    "Data classification, retention, and breach notification procedures",
                    "Disable all international traffic",
                    "Use of only proprietary encryption algorithms"
                ],
                "correctAnswer": 1,
                "category": "Security Program Management and Oversight"
            },
            {
                "question": "The security team conducts a gap analysis and finds that the organization lacks a formal incident response plan. Which document should be created or updated to address this gap?",
                "options": [
                    "Patch management policy",
                    "Incident response policy and playbooks",
                    "User onboarding process",
                    "Disaster recovery plan"
                ],
                "correctAnswer": 1,
                "category": "Security Program Management and Oversight"
            },
            {
                "question": "A security manager needs to track which employees have completed mandatory security awareness training. Which control category does this activity belong to?",
                "options": [
                    "Technical controls",
                    "Operational controls",
                    "Physical controls",
                    "Compensating controls"
                ],
                "correctAnswer": 1,
                "category": "Security Program Management and Oversight"
            },
            {
                "question": "An auditor requests evidence that network device configuration changes are reviewed before deployment. Which documentation BEST satisfies this requirement?",
                "options": [
                    "Change management tickets with peer review sign-offs",
                    "Firewall rulebase export",
                    "Endpoint EDR logs",
                    "User account password policy"
                ],
                "correctAnswer": 0,
                "category": "Security Program Management and Oversight"
            },
            {
                "question": "A company’s risk assessment identifies that outdated third-party library usage in custom applications is a significant risk. Which of the following should be included in the remediation plan?",
                "options": [
                    "Disable all external library usage",
                    "Implement a software bill of materials (SBOM) and schedule periodic patch reviews",
                    "Remove all custom applications",
                    "Use only open-source libraries without checking versions"
                ],
                "correctAnswer": 1,
                "category": "Security Program Management and Oversight"
            },
            {
                "question": "A security committee is reviewing security metrics to gauge program effectiveness. Which of the following is the BEST metric for measuring the security program’s ability to detect real incidents?",
                "options": [
                    "Number of security awareness emails sent",
                    "Mean time to detect (MTTD) security incidents",
                    "Number of firewalls deployed",
                    "Count of network switches"
                ],
                "correctAnswer": 1,
                "category": "Security Program Management and Oversight"
            },
            {
                "question": "A security officer wants to ensure senior management is aware of the current threat landscape. Which type of report should be presented quarterly?",
                "options": [
                    "Vulnerability scan output logs",
                    "Executive-level risk assessment report",
                    "Daily intrusion detection alerts",
                    "Printer usage statistics"
                ],
                "correctAnswer": 1,
                "category": "Security Program Management and Oversight"
            },
            {
                "question": "A development organization wants to integrate security into its Agile development process. Which framework or practice is MOST appropriate to achieve this?",
                "options": [
                    "Continuous Deployment without security reviews",
                    "DevSecOps with automated security testing in CI/CD pipeline",
                    "Waterfall with security sign-offs at the end",
                    "Ad-hoc security checks when developers have time"
                ],
                "correctAnswer": 1,
                "category": "Security Program Management and Oversight"
            },
            {
                "question": "An organization must maintain retention of log data for at least one year for compliance. Which of the following ensures logs remain available and unaltered?",
                "options": [
                    "Write-once, read-many (WORM) storage and regular integrity checks",
                    "Weekly archival to local desktop machines",
                    "Regular use of temporary storage",
                    "Keeping logs on the same server as production data"
                ],
                "correctAnswer": 0,
                "category": "Security Program Management and Oversight"
            },
            {
                "question": "A security manager wants to benchmark the organization’s security posture against industry peers. Which activity should be performed?",
                "options": [
                    "Participate in information sharing and analysis center (ISAC) surveys and peer benchmarking",
                    "Only review internal audit findings",
                    "Disable all third-party connections",
                    "Conduct random social engineering exercises without measurement"
                ],
                "correctAnswer": 0,
                "category": "Security Program Management and Oversight"
            },
            {
                "question": "A security director wants to ensure budget is allocated correctly for upcoming fiscal year. Which analysis will help determine funding priorities?",
                "options": [
                    "Gap analysis between current and desired security capabilities",
                    "Performance reviews of all employees",
                    "Annual office temperature logs",
                    "Weekly team meeting notes"
                ],
                "correctAnswer": 0,
                "category": "Security Program Management and Oversight"
            },
            {
                "question": "A compliance team requires proof that user access reviews are completed every six months. Which artifact would BEST demonstrate adherence?",
                "options": [
                    "User access review logs signed off by managers",
                    "Firewall ACL configurations",
                    "HR recruitment records",
                    "Daily antivirus definitions update logs"
                ],
                "correctAnswer": 0,
                "category": "Security Program Management and Oversight"
            }
        ],
        icon: "fa-shield-alt",
        color: "history",
        difficulty: "Medium",
        participants: 23,
        description: "Prepare for the CompTIA Security+ Exam."
    },
};

// DOM elements
const mainContainer = document.getElementById('main-container');
const quizSelectionPage = document.getElementById('quiz-selection-page');
const quizPage = document.getElementById('quiz-page');
const resultsPage = document.getElementById('results-page');
const quizTitle = document.getElementById('quiz-title');
const quizDifficulty = document.getElementById('quiz-difficulty');
const questionText = document.getElementById('question-text');
const optionsContainer = document.getElementById('options-container');
const nextBtn = document.getElementById('next-btn');
const prevBtn = document.getElementById('prev-btn');
const submitBtn = document.getElementById('submit-btn');
const progressText = document.getElementById('progress-text');
const progressBar = document.querySelector('.progress-bar');
// const timerElement = document.getElementById('timer');
const scoreElement = document.getElementById('score');
const performanceText = document.getElementById('performance-text');
const summaryContainer = document.getElementById('summary-container');
const retryBtn = document.getElementById('retry-btn');
const showAnswersBtn = document.getElementById('show-answers');
const backToQuizzes = document.getElementById('back-to-quizzes');
const backToQuizzesFromResults = document.getElementById('back-to-quizzes-from-results');
const quizCategories = document.getElementById('quiz-categories');

// Quiz state variables
let currentQuizName = "";
let currentQuestionIndex = 0;
let selectedOptions = [];
let scores = 0;

// Generate quiz cards for selection
function generateQuizCards() {
    quizCategories.innerHTML = '';

    for (const [quizName, quizData] of Object.entries(quizzes)) {
        const card = document.createElement('div');
        card.classList.add('quiz-card', 'bg-white', 'rounded-xl', 'border', 'border-gray-100', 'overflow-hidden', 'shadow-md', 'transition-all', 'duration-300', 'cursor-pointer');
        card.dataset.quiz = quizName;

        // Set category color dynamically
        const textColor = `text-${quizData.color}-600`;
        const bgColor = `bg-${quizData.color}-100`;

        card.innerHTML = `
                    <div class="h-1 ${bgColor}"></div>
                    <div class="p-6">
                        <div class="flex items-start mb-4">
                            <div class="flex-shrink-0 w-12 h-12 ${bgColor} rounded-lg flex items-center justify-center mr-4">
                                <i class="fas ${quizData.icon} ${textColor} text-2xl"></i>
                            </div>
                            <div>
                                <h3 class="text-xl font-bold text-gray-800">${quizName}</h3>
                                <p class="text-gray-600 text-sm mt-1">${quizData.description}</p>
                            </div>
                        </div>
                        
                        <div class="flex justify-between mt-4">
                            <div class="flex flex-col">
                                <span class="text-sm text-gray-500">Difficulty</span>
                                <span class="font-medium text-gray-800">${quizData.difficulty}</span>
                            </div>
                            <div class="flex flex-col">
                                <span class="text-sm text-gray-500">Questions</span>
                                <span class="font-medium text-gray-800">${quizData.questions.length}</span>
                            </div>
                        </div>
                        
                        <div class="mt-4 text-xs text-gray-500 flex items-center">
                            <i class="fas fa-users mr-1"></i> 
                            <span>${quizData.participants.toLocaleString()} participants</span>
                        </div>
                    </div>
                    
                    <div class="px-6 py-3 bg-gray-50 border-t border-gray-100">
                        <div class="flex justify-between items-center">
                            <span class="text-gray-600 text-sm">Take the challenge</span>
                            <span class="inline-flex items-center justify-center w-8 h-8 rounded-full ${bgColor}">
                                <i class="fas fa-arrow-right ${textColor} text-sm"></i>
                            </span>
                        </div>
                    </div>
                `;

        card.addEventListener('click', () => startQuiz(quizName));
        quizCategories.appendChild(card);
    }
}

// Start the selected quiz
function startQuiz(quizName) {
    currentQuizName = quizName;
    const quiz = quizzes[quizName];

    // Set quiz header
    quizTitle.textContent = quizName;
    quizDifficulty.textContent = quiz.difficulty;
    quizDifficulty.className = `px-3 py-1 rounded-full text-xs font-medium bg-${quiz.color}-100 text-${quiz.color}-800`;

    // Initialize quiz state
    currentQuestionIndex = 0;
    selectedOptions = Array(quiz.questions.length).fill(null);
    scores = 0;

    // Hide selection and show quiz
    quizSelectionPage.classList.add('hidden');
    quizPage.classList.remove('hidden');

    // Update progress bar
    updateProgressBar();

    // Render first question
    renderQuestion();
}

// Render the current question and options
function renderQuestion() {
    const quiz = quizzes[currentQuizName];
    const question = quiz.questions[currentQuestionIndex];

    questionText.textContent = question.question;

    // Clear previous options
    optionsContainer.innerHTML = '';

    // Create options elements
    question.options.forEach((option, index) => {
        const optionElement = document.createElement('button');
        optionElement.classList.add('option-btn', 'bg-white', 'border', 'border-gray-200', 'rounded-lg', 'p-4', 'text-left', 'transition-all', 'hover:shadow-md');
        optionElement.innerHTML = `
                    <span class="inline-block w-8 h-8 mr-3 rounded-full bg-gray-100 text-center leading-8 font-medium">${String.fromCharCode(65 + index)}</span>
                    ${option}
                `;

        // Check if this option was previously selected
        if (selectedOptions[currentQuestionIndex] === index) {
            optionElement.classList.add('selected', 'bg-blue-50', 'border-blue-300');
        }

        // Handle option selection
        optionElement.addEventListener('click', () => {
            // Remove selected class from all options
            document.querySelectorAll('.option-btn').forEach(btn => {
                btn.classList.remove('selected', 'bg-blue-50', 'border-blue-300');
            });

            // Add selected class to clicked option
            optionElement.classList.add('selected', 'bg-blue-50', 'border-blue-300');
            selectedOptions[currentQuestionIndex] = index;

            // Enable navigation buttons if we have a selection
            if (selectedOptions[currentQuestionIndex] !== null) {
                nextBtn.disabled = false;
            }
        });

        optionsContainer.appendChild(optionElement);
    });

    // Update buttons visibility
    prevBtn.disabled = currentQuestionIndex === 0;
    prevBtn.classList.toggle('invisible', currentQuestionIndex === 0);

    nextBtn.classList.toggle('hidden', currentQuestionIndex === quiz.questions.length - 1);
    submitBtn.classList.toggle('hidden', currentQuestionIndex !== quiz.questions.length - 1);

    // Disable next button until option is selected
    nextBtn.disabled = selectedOptions[currentQuestionIndex] === null;

    // Update progress text
    progressText.textContent = `Question ${currentQuestionIndex + 1} of ${quiz.questions.length}`;
}

// Update progress bar
function updateProgressBar() {
    const quiz = quizzes[currentQuizName];
    const progressPercent = ((currentQuestionIndex) / quiz.questions.length) * 100;
    progressBar.style.width = `${progressPercent}%`;
}

// Navigate to next question
function nextQuestion() {
    const quiz = quizzes[currentQuizName];
    if (currentQuestionIndex < quiz.questions.length - 1) {
        currentQuestionIndex++;
        updateProgressBar();
        renderQuestion();
    }
}

// Navigate to previous question
function prevQuestion() {
    if (currentQuestionIndex > 0) {
        currentQuestionIndex--;
        updateProgressBar();
        renderQuestion();
    }
}

// Finish quiz and show results
function finishQuiz() {
    // Calculate score
    scores = 0;
    const quiz = quizzes[currentQuizName];
    quiz.questions.forEach((question, index) => {
        if (selectedOptions[index] === question.correctAnswer) {
            scores++;
        }
    });

    // Update UI
    quizPage.classList.add('hidden');
    resultsPage.classList.remove('hidden');

    scoreElement.textContent = scores;
    performanceText.parentElement.querySelector('#total-questions').textContent = quiz.questions.length;

    // Performance text based on score
    if (scores >= quiz.questions.length * 0.8) {
        performanceText.textContent = "Outstanding! You really know your stuff.";
        document.getElementById('result-icon').classList.add('bg-gradient-to-r', 'from-green-400', 'to-emerald-500');
    } else if (scores >= quiz.questions.length * 0.6) {
        performanceText.textContent = "Good job! You have solid knowledge.";
        document.getElementById('result-icon').classList.add('bg-gradient-to-r', 'from-blue-400', 'to-indigo-500');
    } else if (scores >= quiz.questions.length * 0.4) {
        performanceText.textContent = "Not bad! You've got room to grow.";
        document.getElementById('result-icon').classList.add('bg-gradient-to-r', 'from-yellow-400', 'to-orange-500');
    } else {
        performanceText.textContent = "Keep learning! Try again to improve.";
        document.getElementById('result-icon').classList.add('bg-gradient-to-r', 'from-red-400', 'to-pink-500');
    }
}

// Generate quiz summary
function generateSummary() {
    summaryContainer.innerHTML = '';
    const quiz = quizzes[currentQuizName];

    quiz.questions.forEach((question, index) => {
        const summaryItem = document.createElement('div');
        summaryItem.classList.add('border-b', 'border-gray-100', 'pb-4', 'last:border-0');

        const userAnswer = selectedOptions[index];
        const isCorrect = userAnswer === question.correctAnswer;

        summaryItem.innerHTML = `
                    <div class="flex justify-between items-center mb-2">
                        <p class="font-medium text-gray-700">Question ${index + 1}: ${question.question}</p>
                        <span class="${isCorrect ? 'text-correct' : 'text-incorrect'} font-bold">
                            ${isCorrect ? '<i class="fas fa-check mr-1"></i> Correct' : '<i class="fas fa-times mr-1"></i> Incorrect'}
                        </span>
                    </div>
                    <div class="grid grid-cols-1 md:grid-cols-2 gap-2">
                        <div>
                            <p class="font-medium text-gray-600 mb-1">Your Answer:</p>
                            <div class="${isCorrect ? 'bg-green-50 border-green-200' : 'bg-red-50 border-red-200'} border rounded-lg p-2">
                                ${userAnswer !== null ? question.options[userAnswer] : 'No answer'}
                            </div>
                        </div>
                        ${isCorrect ? '' : `
                        <div>
                            <p class="font-medium text-gray-600 mb-1">Correct Answer:</p>
                            <div class="bg-green-50 border border-green-200 rounded-lg p-2">
                                ${question.options[question.correctAnswer]}
                            </div>
                        </div>
                        `}
                    </div>
                `;

        summaryContainer.appendChild(summaryItem);
    });
}

// Event listeners
document.addEventListener('DOMContentLoaded', () => {
    generateQuizCards();

    // Tab switching logic
    const tabButtons = document.querySelectorAll('.tab-btn');
    tabButtons.forEach(btn => {
        btn.addEventListener('click', () => {
            tabButtons.forEach(b => b.classList.remove('bg-white', 'shadow'));
            btn.classList.add('bg-white', 'shadow');
        });
    });

    // Add an initial active state to the "Popular" tab
    document.getElementById('popular-tab').classList.add('bg-white', 'shadow');
});

nextBtn.addEventListener('click', nextQuestion);
prevBtn.addEventListener('click', prevQuestion);
submitBtn.addEventListener('click', finishQuiz);

retryBtn.addEventListener('click', () => {
    resultsPage.classList.add('hidden');
    startQuiz(currentQuizName);
});

backToQuizzes.addEventListener('click', () => {
    quizPage.classList.add('hidden');
    quizSelectionPage.classList.remove('hidden');
});

backToQuizzesFromResults.addEventListener('click', () => {
    resultsPage.classList.add('hidden');
    quizSelectionPage.classList.remove('hidden');
});

showAnswersBtn.addEventListener('click', generateSummary);