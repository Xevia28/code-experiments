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
    "Essentials of Networking": {
        questions: [
            {
                "question": "Which layer of the OSI model is responsible for end-to-end communication and error recovery?",
                "options": ["Network", "Transport", "Data Link", "Session"],
                "correctAnswer": 1,
                "category": "OSI Model"
            },
            {
                "question": "Which OSI layer handles routing between devices on different networks?",
                "options": ["Transport", "Session", "Network", "Data Link"],
                "correctAnswer": 2,
                "category": "OSI Model"
            },
            {
                "question": "In the TCP/IP model, what layer is equivalent to the OSI's Network layer?",
                "options": ["Application", "Transport", "Internet", "Link"],
                "correctAnswer": 2,
                "category": "TCP/IP Model"
            },
            {
                "question": "How many bits are in an IPv4 address?",
                "options": ["16", "32", "64", "128"],
                "correctAnswer": 1,
                "category": "TCP/IP Model"
            },
            {
                "question": "What is the CIDR notation for a subnet mask of 255.255.255.192?",
                "options": ["/24", "/25", "/26", "/27"],
                "correctAnswer": 2,
                "category": "Subnetting"
            },
            {
                "question": "How many usable hosts can you have in a /28 network?",
                "options": ["14", "16", "30", "32"],
                "correctAnswer": 0,
                "category": "Subnetting"
            },
            {
                "question": "Which topology connects all devices to a single central device?",
                "options": ["Bus", "Ring", "Mesh", "Star"],
                "correctAnswer": 3,
                "category": "Network Topologies"
            },
            {
                "question": "Which topology provides the most redundancy?",
                "options": ["Star", "Mesh", "Bus", "Ring"],
                "correctAnswer": 1,
                "category": "Network Topologies"
            },
            {
                "question": "What type of network spans a city or large campus?",
                "options": ["LAN", "WAN", "MAN", "PAN"],
                "correctAnswer": 2,
                "category": "Network Types"
            },
            {
                "question": "What is the largest type of network by geographical scope?",
                "options": ["LAN", "MAN", "WAN", "PAN"],
                "correctAnswer": 2,
                "category": "Network Types"
            },
            {
                "question": "Which of the following separates the control plane from the data plane?",
                "options": ["NFV", "MPLS", "SD-WAN", "SDN"],
                "correctAnswer": 3,
                "category": "SDN, NFV, SD-WAN"
            },
            {
                "question": "Which technology uses virtualization to abstract network functions from hardware?",
                "options": ["SDN", "NFV", "VLAN", "MPLS"],
                "correctAnswer": 1,
                "category": "SDN, NFV, SD-WAN"
            },
            {
                "question": "Which protocol is used to assign IP addresses dynamically?",
                "options": ["DNS", "DHCP", "FTP", "SMTP"],
                "correctAnswer": 1,
                "category": "Network Protocols"
            },
            {
                "question": "Which protocol translates domain names into IP addresses?",
                "options": ["DNS", "DHCP", "SMTP", "FTP"],
                "correctAnswer": 0,
                "category": "Network Protocols"
            },
            {
                "question": "Which of the following protocols is used to send emails?",
                "options": ["HTTP", "DHCP", "SMTP", "DNS"],
                "correctAnswer": 2,
                "category": "Network Protocols"
            },
            {
                "question": "Which protocol ensures secure communication over HTTP?",
                "options": ["HTTPS", "FTP", "SMTP", "DNS"],
                "correctAnswer": 0,
                "category": "Network Protocols"
            },
            {
                "question": "What does NAT do?",
                "options": [
                    "Provides encryption for data",
                    "Assigns MAC addresses",
                    "Translates private IPs to public IPs",
                    "Routes packets over the Internet"
                ],
                "correctAnswer": 2,
                "category": "NAT"
            },
            {
                "question": "Which type of NAT maps one private IP to one public IP?",
                "options": ["Static NAT", "Dynamic NAT", "PAT", "SNAT"],
                "correctAnswer": 0,
                "category": "NAT"
            },
            {
                "question": "Which technology uses labels instead of IP addresses to forward packets?",
                "options": ["VLAN", "NAT", "MPLS", "OSPF"],
                "correctAnswer": 2,
                "category": "MPLS"
            },
            {
                "question": "MPLS primarily improves what aspect of networking?",
                "options": ["IP address allocation", "Packet routing speed", "MAC filtering", "Email delivery"],
                "correctAnswer": 1,
                "category": "MPLS"
            },
            {
                "question": "What is the main purpose of a VPN?",
                "options": [
                    "Speed up local area networks",
                    "Encrypt and tunnel network traffic",
                    "Assign dynamic IP addresses",
                    "Prevent phishing attacks"
                ],
                "correctAnswer": 1,
                "category": "VPN"
            },
            {
                "question": "Which protocol is commonly used to create VPN tunnels?",
                "options": ["FTP", "IPSec", "SMTP", "HTTP"],
                "correctAnswer": 1,
                "category": "VPN"
            },
            {
                "question": "What does a VLAN allow you to do?",
                "options": [
                    "Create multiple physical networks",
                    "Create virtual networks within a physical switch",
                    "Assign static IPs",
                    "Route traffic to the Internet"
                ],
                "correctAnswer": 1,
                "category": "VLANs"
            },
            {
                "question": "Which of the following is a benefit of using VLANs?",
                "options": [
                    "Decreased IP range",
                    "Improved DNS performance",
                    "Improved network segmentation and security",
                    "Increased DHCP leases"
                ],
                "correctAnswer": 2,
                "category": "VLANs"
            },
            {
                "question": "Which routing protocol is considered a link-state protocol?",
                "options": ["RIP", "BGP", "EIGRP", "OSPF"],
                "correctAnswer": 3,
                "category": "Routing"
            },
            {
                "question": "Which routing protocol is used between different autonomous systems?",
                "options": ["OSPF", "EIGRP", "BGP", "RIP"],
                "correctAnswer": 2,
                "category": "Routing"
            },
            {
                "question": "What is a main advantage of dynamic routing over static routing?",
                "options": [
                    "Easier to configure",
                    "Better performance",
                    "Adapts to network changes automatically",
                    "More secure"
                ],
                "correctAnswer": 2,
                "category": "Routing"
            },
            {
                "question": "Which protocol uses DUAL algorithm for routing?",
                "options": ["OSPF", "BGP", "RIP", "EIGRP"],
                "correctAnswer": 3,
                "category": "Routing"
            },
            {
                "question": "Which feature ensures high availability of a network by distributing traffic across multiple servers?",
                "options": ["Firewall", "Load Balancing", "NAT", "VPN"],
                "correctAnswer": 1,
                "category": "Load Balancing and Redundancy"
            },
            {
                "question": "What is the purpose of network redundancy?",
                "options": [
                    "To provide additional IP addresses",
                    "To ensure network availability in case of failure",
                    "To balance network traffic",
                    "To translate IP addresses"
                ],
                "correctAnswer": 1,
                "category": "Load Balancing and Redundancy"
            },
            {
                "question": "What is the main function of a firewall?",
                "options": [
                    "Speed up traffic",
                    "Translate IP addresses",
                    "Filter incoming and outgoing traffic",
                    "Assign MAC addresses"
                ],
                "correctAnswer": 2,
                "category": "Firewall Basics"
            },
            {
                "question": "Which type of firewall filters traffic based on application-layer data?",
                "options": ["Packet-filtering", "Stateful", "Proxy", "Circuit-level"],
                "correctAnswer": 2,
                "category": "Firewall Basics"
            },
            {
                "question": "Which wireless encryption protocol is considered the most secure?",
                "options": ["WEP", "WPA", "WPA2", "WPA3"],
                "correctAnswer": 3,
                "category": "Wireless Network Security"
            },
            {
                "question": "Which of the following is a common wireless security threat?",
                "options": ["Packet flooding", "War driving", "NAT overflow", "MAC filtering"],
                "correctAnswer": 1,
                "category": "Wireless Network Security"
            },
            {
                "question": "What does IDS stand for?",
                "options": ["Internet Detection System", "Intrusion Detection System", "Internal Defense System", "Integrated Defense Suite"],
                "correctAnswer": 1,
                "category": "IDS/IPS"
            },
            {
                "question": "Which of the following can block malicious traffic in real time?",
                "options": ["IDS", "Firewall", "IPS", "Proxy"],
                "correctAnswer": 2,
                "category": "IDS/IPS"
            },
            {
                "question": "Which OSI layer is responsible for data formatting and encryption?",
                "options": ["Session", "Presentation", "Application", "Transport"],
                "correctAnswer": 1,
                "category": "OSI Model"
            },
            {
                "question": "At which OSI layer do switches operate?",
                "options": ["Network", "Data Link", "Transport", "Physical"],
                "correctAnswer": 1,
                "category": "OSI Model"
            },
            {
                "question": "Which device typically operates at Layer 3 of the OSI model?",
                "options": ["Hub", "Switch", "Router", "Repeater"],
                "correctAnswer": 2,
                "category": "OSI Model"
            },
            {
                "question": "Which TCP/IP layer is responsible for reliable end-to-end communication?",
                "options": ["Network", "Transport", "Application", "Link"],
                "correctAnswer": 1,
                "category": "TCP/IP Model"
            },
            {
                "question": "What is the primary advantage of SD-WAN over traditional WANs?",
                "options": [
                    "More expensive hardware",
                    "Centralized control and optimization",
                    "Better DHCP support",
                    "Improved firewall configuration"
                ],
                "correctAnswer": 1,
                "category": "SDN, NFV, SD-WAN"
            },
            {
                "question": "Which of the following uses port 21 by default?",
                "options": ["FTP", "HTTP", "SSH", "SMTP"],
                "correctAnswer": 0,
                "category": "Network Protocols"
            },
            {
                "question": "What does CIDR stand for?",
                "options": [
                    "Classless Inter-Domain Routing",
                    "Computer Internet Data Routing",
                    "Control Information Data Rate",
                    "Core Internet Dynamic Routing"
                ],
                "correctAnswer": 0,
                "category": "Subnetting"
            },
            {
                "question": "Which class of IP address offers up to 16,777,214 hosts per network?",
                "options": ["Class A", "Class B", "Class C", "Class D"],
                "correctAnswer": 0,
                "category": "Subnetting"
            },
            {
                "question": "What is a characteristic of a full mesh topology?",
                "options": [
                    "Each device connects to a central hub",
                    "Each device connects to exactly two others",
                    "Each device is connected to every other device",
                    "All devices connect using a single backbone cable"
                ],
                "correctAnswer": 2,
                "category": "Network Topologies"
            },
            {
                "question": "Which device combines multiple signals into one and sends it over a single line?",
                "options": ["Hub", "Multiplexer", "Switch", "Repeater"],
                "correctAnswer": 1,
                "category": "General Networking"
            },
            {
                "question": "Which routing protocol uses path vector logic and is commonly used on the Internet?",
                "options": ["OSPF", "RIP", "EIGRP", "BGP"],
                "correctAnswer": 3,
                "category": "Routing"
            },
            {
                "question": "Which of the following is a function of an IDS but NOT of a traditional firewall?",
                "options": [
                    "Blocking traffic based on port",
                    "Allowing traffic based on IP address",
                    "Monitoring and alerting on suspicious activity",
                    "Performing NAT"
                ],
                "correctAnswer": 2,
                "category": "IDS/IPS"
            },
            {
                "question": "Which type of address is used to communicate with all hosts on a network segment?",
                "options": ["Unicast", "Anycast", "Multicast", "Broadcast"],
                "correctAnswer": 3,
                "category": "General Networking"
            },
            {
                "question": "What type of VPN is most commonly used to connect remote users securely to a corporate network?",
                "options": ["Site-to-Site VPN", "Remote Access VPN", "PPTP VPN", "Layer 2 VPN"],
                "correctAnswer": 1,
                "category": "VPN"
            }
        ],
        icon: "fa-user-shield",
        color: "cybersecurity",
        difficulty: "Easy",
        participants: 15,
        description: "Test your knowledge of basic cybersecurity concepts."
    },
    "CEH Lesson 1": {
        questions: [
            {
                "question": "Which of the following is a fundamental principle of the CIA Triad?",
                "options": [
                    "Confidentiality, Integrity, Accountability",
                    "Confidentiality, Integrity, Availability",
                    "Cryptography, Integrity, Availability",
                    "Authentication, Authorization, Accounting"
                ],
                "correctAnswer": 1,
                "category": "General Security Concepts"
            },
            {
                "question": "Which of the following types of hackers performs attacks for malicious purposes, often for personal gain?",
                "options": [
                    "White Hat",
                    "Black Hat",
                    "Gray Hat",
                    "Hacktivist"
                ],
                "correctAnswer": 1,
                "category": "Ethical Hacking"
            },
            {
                "question": "The CEH Ethical Hacking Framework is used for which of the following?",
                "options": [
                    "To assess system vulnerabilities in a structured manner",
                    "To train hackers for malicious purposes",
                    "To create hacking tools",
                    "To patch system vulnerabilities"
                ],
                "correctAnswer": 0,
                "category": "Ethical Hacking Frameworks"
            },
            {
                "question": "Which of the following standards is critical for securing financial transactions and ensuring compliance in the payment card industry?",
                "options": [
                    "HIPAA",
                    "PCI DSS",
                    "GDPR",
                    "FISMA"
                ],
                "correctAnswer": 1,
                "category": "Risk & Compliance"
            },
            {
                "question": "Which of the following is NOT a risk management strategy?",
                "options": [
                    "Risk Acceptance",
                    "Risk Transference",
                    "Risk Avoidance",
                    "Risk Exposure"
                ],
                "correctAnswer": 3,
                "category": "Risk & Compliance"
            },
            {
                "question": "What is the main goal of ethical hacking?",
                "options": [
                    "To exploit vulnerabilities for financial gain",
                    "To discover and fix vulnerabilities before they are exploited",
                    "To create hacking tools",
                    "To conduct attacks on systems"
                ],
                "correctAnswer": 1,
                "category": "Ethical Hacking"
            },
            {
                "question": "Which of the following best describes a black hat hacker?",
                "options": [
                    "A hacker who works to identify and report vulnerabilities",
                    "A hacker who attacks for malicious purposes",
                    "A hacker hired by organizations to test security",
                    "A hacker who sells exploits to others"
                ],
                "correctAnswer": 1,
                "category": "Ethical Hacking"
            },
            {
                "question": "Which of the following is an example of social engineering?",
                "options": [
                    "SQL injection",
                    "Phishing",
                    "Cross-Site Scripting (XSS)",
                    "Buffer overflow"
                ],
                "correctAnswer": 1,
                "category": "Ethical Hacking Techniques"
            },
            {
                "question": "Which of the following standards focuses on the protection of healthcare information?",
                "options": [
                    "PCI DSS",
                    "HIPAA",
                    "GDPR",
                    "FISMA"
                ],
                "correctAnswer": 1,
                "category": "Risk & Compliance"
            },
            {
                "question": "What is the role of a penetration tester in ethical hacking?",
                "options": [
                    "To defend systems against attacks",
                    "To identify and exploit vulnerabilities in systems",
                    "To deploy malware on a system",
                    "To create hacking tools"
                ],
                "correctAnswer": 1,
                "category": "Ethical Hacking"
            },
            {
                "question": "Which of the following ethical hacking frameworks provides a step-by-step methodology for conducting a security assessment?",
                "options": [
                    "Cyber Kill Chain",
                    "MITRE ATT&CK",
                    "CEH Methodology",
                    "OWASP Top 10"
                ],
                "correctAnswer": 2,
                "category": "Ethical Hacking Frameworks"
            },
            {
                "question": "In the CEH framework, which phase is focused on gathering information from public sources?",
                "options": [
                    "Reconnaissance",
                    "Exploitation",
                    "Reporting",
                    "Post-exploitation"
                ],
                "correctAnswer": 0,
                "category": "Ethical Hacking Frameworks"
            },
            {
                "question": "What is the purpose of the risk management framework?",
                "options": [
                    "To patch vulnerabilities",
                    "To identify, assess, and mitigate risks",
                    "To perform penetration testing",
                    "To deploy security patches"
                ],
                "correctAnswer": 1,
                "category": "Risk Management"
            },
            {
                "question": "Which type of attack involves unauthorized access to confidential data for malicious purposes?",
                "options": [
                    "Phishing",
                    "Spyware",
                    "Data Breach",
                    "Man-in-the-Middle"
                ],
                "correctAnswer": 2,
                "category": "Types of Attacks"
            },
            {
                "question": "Which ethical hacking framework is specifically designed for cyberattack prevention and threat analysis?",
                "options": [
                    "MITRE ATT&CK",
                    "Cyber Kill Chain",
                    "CEH Methodology",
                    "OWASP Top 10"
                ],
                "correctAnswer": 1,
                "category": "Ethical Hacking Frameworks"
            }
        ],
        icon: "fa-user-shield",
        color: "cybersecurity",
        difficulty: "Easy",
        participants: 6,
        description: "Test your knowledge of basic cybersecurity concepts."
    },
    "CEH Lesson 2": {
        questions: [
            {
                "question": "Which technique is typically used to gather information without directly interacting with the target?",
                "options": [
                    "Active Footprinting",
                    "Passive Footprinting",
                    "Port Scanning",
                    "OS Fingerprinting"
                ],
                "correctAnswer": 1,
                "category": "Footprinting & Reconnaissance"
            },
            {
                "question": "Which of the following tools is used to gather open-source intelligence (OSINT)?",
                "options": [
                    "Maltego",
                    "Nmap",
                    "Metasploit",
                    "Wireshark"
                ],
                "correctAnswer": 0,
                "category": "OSINT Tools"
            },
            {
                "question": "What type of information can be gathered by performing a WHOIS query during reconnaissance?",
                "options": [
                    "IP address of a web server",
                    "Website content",
                    "Owner of the domain",
                    "DNS records"
                ],
                "correctAnswer": 2,
                "category": "Footprinting Techniques"
            },
            {
                "question": "Which of the following is an example of an active reconnaissance technique?",
                "options": [
                    "Social media scraping",
                    "DNS querying",
                    "Ping sweep",
                    "Website scraping"
                ],
                "correctAnswer": 2,
                "category": "Reconnaissance Techniques"
            },
            {
                "question": "What does a DNS Zone Transfer allow an attacker to do?",
                "options": [
                    "Steal DNS records from the target",
                    "Hijack DNS servers",
                    "Redirect DNS requests to malicious servers",
                    "Identify subdomains of a domain"
                ],
                "correctAnswer": 3,
                "category": "DNS Enumeration"
            },
            {
                "question": "Which of the following is a social media platform that can be exploited during footprinting?",
                "options": [
                    "LinkedIn",
                    "Facebook",
                    "Twitter",
                    "All of the above"
                ],
                "correctAnswer": 3,
                "category": "Social Media Footprinting"
            },
            {
                "question": "Which reconnaissance technique is typically used to identify open ports on a target system?",
                "options": [
                    "Ping sweep",
                    "Port scanning",
                    "OS fingerprinting",
                    "DNS enumeration"
                ],
                "correctAnswer": 1,
                "category": "Reconnaissance Techniques"
            },
            {
                "question": "Which of the following is the purpose of a reverse lookup in DNS footprinting?",
                "options": [
                    "To identify the IP address of a domain",
                    "To discover the domain name of an IP address",
                    "To check the availability of a domain",
                    "To identify the DNS server of a domain"
                ],
                "correctAnswer": 1,
                "category": "DNS Enumeration"
            },
            {
                "question": "Which of the following OSINT tools can be used for footprinting a target's physical location based on IP address?",
                "options": [
                    "Shodan",
                    "Maltego",
                    "Recon-ng",
                    "Wireshark"
                ],
                "correctAnswer": 0,
                "category": "OSINT Tools"
            },
            {
                "question": "What information can be extracted by performing a search engine hacking technique?",
                "options": [
                    "Sensitive files or information left unprotected",
                    "Web server vulnerabilities",
                    "Network configurations",
                    "All of the above"
                ],
                "correctAnswer": 0,
                "category": "Search Engine Hacking"
            },
            {
                "question": "Which of the following attacks can be initiated using insecure or exposed APIs?",
                "options": [
                    "SQL Injection",
                    "Man-in-the-Middle",
                    "API abuse",
                    "Buffer overflow"
                ],
                "correctAnswer": 2,
                "category": "API Exploitation"
            },
            {
                "question": "Which of the following is a tool used to perform DNS footprinting?",
                "options": [
                    "Wireshark",
                    "Recon-ng",
                    "Nslookup",
                    "Metasploit"
                ],
                "correctAnswer": 2,
                "category": "DNS Enumeration"
            },
            {
                "question": "Which of the following techniques can be used to gather information from a target system without triggering an alert?",
                "options": [
                    "Active reconnaissance",
                    "Passive reconnaissance",
                    "Port scanning",
                    "Phishing"
                ],
                "correctAnswer": 1,
                "category": "Reconnaissance Techniques"
            }
        ],
        icon: "fa-user-shield",
        color: "cybersecurity",
        difficulty: "Easy",
        participants: 6,
        description: "Test your knowledge of basic cybersecurity concepts."
    },
    "CEH Lesson 3": {
        questions: [
            {
                "question": "Which of the following tools is used for network scanning?",
                "options": [
                    "Wireshark",
                    "Metasploit",
                    "Nmap",
                    "Burp Suite"
                ],
                "correctAnswer": 2,
                "category": "Network Scanning Tools"
            },
            {
                "question": "What type of scan can be used to detect open ports on a target system?",
                "options": [
                    "Port scanning",
                    "OS fingerprinting",
                    "DNS enumeration",
                    "DNS lookup"
                ],
                "correctAnswer": 0,
                "category": "Scanning Techniques"
            },
            {
                "question": "Which of the following is a type of stealth scan?",
                "options": [
                    "Ping Sweep",
                    "SYN Scan",
                    "UDP Scan",
                    "Service Detection"
                ],
                "correctAnswer": 1,
                "category": "Scanning Techniques"
            },
            {
                "question": "Which scanning technique is typically used to detect live systems on a network?",
                "options": [
                    "Stealth scan",
                    "Ping Sweep",
                    "Service Scan",
                    "OS Scan"
                ],
                "correctAnswer": 1,
                "category": "Scanning Techniques"
            },
            {
                "question": "Which of the following is an example of a vulnerability scanning tool?",
                "options": [
                    "Nessus",
                    "Nmap",
                    "Metasploit",
                    "Wireshark"
                ],
                "correctAnswer": 0,
                "category": "Vulnerability Scanning"
            },
            {
                "question": "What is the primary objective of banner grabbing?",
                "options": [
                    "To identify open ports",
                    "To discover vulnerabilities",
                    "To gather information about services running on open ports",
                    "To scan for malware"
                ],
                "correctAnswer": 2,
                "category": "Scanning Techniques"
            },
            {
                "question": "What does a SYN scan allow attackers to do?",
                "options": [
                    "Establish a full TCP connection",
                    "Detect live hosts",
                    "Identify operating systems",
                    "Identify open ports without completing the TCP handshake"
                ],
                "correctAnswer": 3,
                "category": "Scanning Techniques"
            },
            {
                "question": "Which technique is used to scan a network for all open ports on all devices?",
                "options": [
                    "Service scan",
                    "Full scan",
                    "ICMP scan",
                    "Ping sweep"
                ],
                "correctAnswer": 1,
                "category": "Scanning Techniques"
            },
            {
                "question": "What is the purpose of an OS fingerprinting scan?",
                "options": [
                    "To identify operating systems on the network",
                    "To discover open ports",
                    "To identify devices in a network",
                    "To exploit vulnerabilities"
                ],
                "correctAnswer": 0,
                "category": "Scanning Techniques"
            },
            {
                "question": "What is the main objective of a UDP scan?",
                "options": [
                    "To identify open ports using the UDP protocol",
                    "To identify active devices",
                    "To detect service versions",
                    "To gather information about the operating system"
                ],
                "correctAnswer": 0,
                "category": "Scanning Techniques"
            },
            {
                "question": "What is the primary purpose of a vulnerability scan?",
                "options": [
                    "To find open ports on a network",
                    "To detect malware on a system",
                    "To assess security weaknesses in a system",
                    "To scan for software updates"
                ],
                "correctAnswer": 2,
                "category": "Vulnerability Scanning"
            },
            {
                "question": "Which type of scanning tool is used to identify services running on open ports?",
                "options": [
                    "Ping sweep",
                    "Service detection",
                    "Vulnerability scan",
                    "OS fingerprinting"
                ],
                "correctAnswer": 1,
                "category": "Scanning Tools"
            },
            {
                "question": "Which scanning technique can be used to detect vulnerabilities on a network?",
                "options": [
                    "OS fingerprinting",
                    "Service detection",
                    "Port scanning",
                    "Vulnerability scanning"
                ],
                "correctAnswer": 3,
                "category": "Scanning Techniques"
            }
        ],
        icon: "fa-user-shield",
        color: "cybersecurity",
        difficulty: "Easy",
        participants: 6,
        description: "Test your knowledge of basic cybersecurity concepts."
    },
    "CEH Lesson 4": {
        questions: [
            {
                "question": "What is the purpose of NetBIOS enumeration in network reconnaissance?",
                "options": [
                    "To extract user lists and shared resources from Windows machines",
                    "To scan for open ports on a network",
                    "To determine the operating system of a target",
                    "To identify vulnerabilities in the target"
                ],
                "correctAnswer": 0,
                "category": "Enumeration Techniques"
            },
            {
                "question": "Which of the following tools is commonly used for SNMP enumeration?",
                "options": [
                    "SNMPWalk",
                    "Nessus",
                    "Wireshark",
                    "Metasploit"
                ],
                "correctAnswer": 0,
                "category": "Enumeration Tools"
            },
            {
                "question": "What type of data can be gathered via LDAP enumeration?",
                "options": [
                    "Usernames and group information",
                    "Open ports and service versions",
                    "Subdomain names and DNS records",
                    "Routing tables"
                ],
                "correctAnswer": 0,
                "category": "Enumeration Techniques"
            },
            {
                "question": "Which vulnerability can be exploited by attackers using DNS enumeration?",
                "options": [
                    "DNS Zone Transfer",
                    "Buffer Overflow",
                    "SQL Injection",
                    "Cross-Site Scripting"
                ],
                "correctAnswer": 0,
                "category": "Enumeration Attacks"
            },
            {
                "question": "Which of the following is a common method used to prevent enumeration attacks?",
                "options": [
                    "Limiting user privileges",
                    "Disabling unnecessary services",
                    "Enabling two-factor authentication",
                    "Using strong passwords"
                ],
                "correctAnswer": 1,
                "category": "Countermeasures"
            },
            {
                "question": "What is the primary goal of enumeration in ethical hacking?",
                "options": [
                    "To exploit vulnerabilities",
                    "To gather detailed information about the target system",
                    "To access sensitive data",
                    "To bypass security measures"
                ],
                "correctAnswer": 1,
                "category": "General Enumeration"
            },
            {
                "question": "Which of the following protocols is used for gathering detailed information about devices in a network during enumeration?",
                "options": [
                    "SNMP",
                    "HTTP",
                    "HTTPS",
                    "FTP"
                ],
                "correctAnswer": 0,
                "category": "Enumeration Techniques"
            },
            {
                "question": "Which type of enumeration targets the exchange of data within a directory service?",
                "options": [
                    "LDAP enumeration",
                    "SNMP enumeration",
                    "SMB enumeration",
                    "NTP enumeration"
                ],
                "correctAnswer": 0,
                "category": "Enumeration Techniques"
            },
            {
                "question": "What does a typical DNS Zone Transfer allow an attacker to do?",
                "options": [
                    "Enumerate all domain names and associated IP addresses",
                    "Manipulate DNS records",
                    "Hijack the DNS server",
                    "Steal sensitive data"
                ],
                "correctAnswer": 0,
                "category": "DNS Enumeration"
            },
            {
                "question": "What is the best defense against LDAP enumeration?",
                "options": [
                    "Disabling unused ports",
                    "Using strong authentication for directory services",
                    "Blocking all inbound traffic to DNS servers",
                    "Encrypting all LDAP traffic"
                ],
                "correctAnswer": 1,
                "category": "Countermeasures"
            },
            {
                "question": "Which of the following is an OSINT tool used for performing reconnaissance on a target system?",
                "options": [
                    "Maltego",
                    "Metasploit",
                    "Nessus",
                    "Wireshark"
                ],
                "correctAnswer": 0,
                "category": "OSINT Tools"
            },
            {
                "question": "Which of the following is a vulnerability often associated with poorly configured DNS servers?",
                "options": [
                    "DNS Zone Transfer",
                    "Port Scanning",
                    "OS Fingerprinting",
                    "ICMP Sweeping"
                ],
                "correctAnswer": 0,
                "category": "DNS Enumeration"
            },
            {
                "question": "Which type of service can be exploited to enumerate email accounts using SMTP enumeration?",
                "options": [
                    "DNS",
                    "HTTP",
                    "SMTP",
                    "SNMP"
                ],
                "correctAnswer": 2,
                "category": "Service Enumeration"
            }
        ],
        icon: "fa-user-shield",
        color: "cybersecurity",
        difficulty: "Easy",
        participants: 6,
        description: "Test your knowledge of basic cybersecurity concepts."
    },
    "CEH Lesson 5": {
        questions: [
            {
                "question": "Which of the following is a common vulnerability assessment tool?",
                "options": [
                    "Nessus",
                    "Metasploit",
                    "Wireshark",
                    "Burp Suite"
                ],
                "correctAnswer": 0,
                "category": "Vulnerability Assessment Tools"
            },
            {
                "question": "What is the main objective of vulnerability scanning?",
                "options": [
                    "To exploit vulnerabilities",
                    "To identify and assess vulnerabilities in systems",
                    "To patch vulnerabilities",
                    "To create new vulnerabilities"
                ],
                "correctAnswer": 1,
                "category": "Vulnerability Management"
            },
            {
                "question": "Which of the following is NOT part of the vulnerability lifecycle?",
                "options": [
                    "Discovery",
                    "Classification",
                    "Exploitation",
                    "Remediation"
                ],
                "correctAnswer": 2,
                "category": "Vulnerability Lifecycle"
            },
            {
                "question": "Which of the following is a risk management strategy for mitigating vulnerabilities?",
                "options": [
                    "Risk Avoidance",
                    "Risk Transference",
                    "Risk Acceptance",
                    "All of the above"
                ],
                "correctAnswer": 3,
                "category": "Risk Management"
            },
            {
                "question": "What is the purpose of a vulnerability assessment report?",
                "options": [
                    "To identify and exploit vulnerabilities",
                    "To document identified vulnerabilities and suggest remediation",
                    "To provide a checklist for patching systems",
                    "To store the vulnerability database"
                ],
                "correctAnswer": 1,
                "category": "Vulnerability Assessment Reporting"
            },
            {
                "question": "Which of the following is NOT a step in a vulnerability management process?",
                "options": [
                    "Discovery",
                    "Prioritization",
                    "Exploitation",
                    "Remediation"
                ],
                "correctAnswer": 2,
                "category": "Vulnerability Management"
            },
            {
                "question": "What is the primary purpose of vulnerability scanning?",
                "options": [
                    "To find open ports on a network",
                    "To detect malware on a system",
                    "To assess security weaknesses in a system",
                    "To scan for software updates"
                ],
                "correctAnswer": 2,
                "category": "Vulnerability Scanning"
            },
            {
                "question": "Which of the following is an example of a vulnerability scanner?",
                "options": [
                    "Metasploit",
                    "Wireshark",
                    "Nessus",
                    "Burp Suite"
                ],
                "correctAnswer": 2,
                "category": "Vulnerability Scanning Tools"
            },
            {
                "question": "Which of the following best describes the goal of a vulnerability management program (VMP)?",
                "options": [
                    "To patch vulnerabilities",
                    "To identify, evaluate, and mitigate vulnerabilities proactively",
                    "To monitor network traffic",
                    "To exploit vulnerabilities"
                ],
                "correctAnswer": 1,
                "category": "Vulnerability Management"
            },
            {
                "question": "Which of the following is a characteristic of a vulnerability scanner?",
                "options": [
                    "It identifies network devices and their services",
                    "It scans only for open ports",
                    "It is used to exploit identified vulnerabilities",
                    "It only identifies malware on a system"
                ],
                "correctAnswer": 0,
                "category": "Vulnerability Scanning Tools"
            },
            {
                "question": "Which of the following is a common issue identified by vulnerability scanning?",
                "options": [
                    "Misconfigured firewall rules",
                    "Unpatched software vulnerabilities",
                    "Weak passwords",
                    "All of the above"
                ],
                "correctAnswer": 3,
                "category": "Vulnerability Scanning"
            },
            {
                "question": "Which of the following scanning methods focuses on identifying vulnerabilities in a web application?",
                "options": [
                    "Network scanning",
                    "Port scanning",
                    "Web application scanning",
                    "OS fingerprinting"
                ],
                "correctAnswer": 2,
                "category": "Vulnerability Scanning"
            },
            {
                "question": "What is the key purpose of patch management in vulnerability management?",
                "options": [
                    "To ensure that vulnerabilities are identified",
                    "To apply security updates and close identified vulnerabilities",
                    "To monitor for threats and attacks",
                    "To provide real-time threat intelligence"
                ],
                "correctAnswer": 1,
                "category": "Patch Management"
            }
        ],
        icon: "fa-user-shield",
        color: "cybersecurity",
        difficulty: "Easy",
        participants: 6,
        description: "Test your knowledge of basic cybersecurity concepts."
    },
    "CEH Lesson 6": {
        questions: [
            {
                "question": "Which of the following is used to gain unauthorized access to a target system?",
                "options": [
                    "Password Cracking",
                    "Port Scanning",
                    "OS Fingerprinting",
                    "DNS Enumeration"
                ],
                "correctAnswer": 0,
                "category": "System Hacking"
            },
            {
                "question": "What is the main objective of privilege escalation?",
                "options": [
                    "To exploit a system vulnerability",
                    "To gain unauthorized access to system files",
                    "To increase access rights to the target system",
                    "To deploy malware on the target system"
                ],
                "correctAnswer": 2,
                "category": "Privilege Escalation"
            },
            {
                "question": "Which of the following techniques is commonly used to bypass authentication in system hacking?",
                "options": [
                    "Brute Force Attacks",
                    "Password Cracking",
                    "Man-in-the-Middle Attack",
                    "Phishing"
                ],
                "correctAnswer": 1,
                "category": "Password Cracking"
            },
            {
                "question": "Which of the following is a countermeasure for preventing privilege escalation?",
                "options": [
                    "Enforcing least privilege",
                    "Using weak passwords",
                    "Allowing root access",
                    "Disabling firewalls"
                ],
                "correctAnswer": 0,
                "category": "Countermeasures"
            },
            {
                "question": "Which of the following types of attack targets the buffer overflow vulnerability?",
                "options": [
                    "Buffer Overflow Attack",
                    "SQL Injection",
                    "Cross-Site Scripting",
                    "Denial-of-Service"
                ],
                "correctAnswer": 0,
                "category": "Exploitation Techniques"
            },
            {
                "question": "Which of the following tools is used for password cracking?",
                "options": [
                    "Wireshark",
                    "John the Ripper",
                    "Metasploit",
                    "Nessus"
                ],
                "correctAnswer": 1,
                "category": "System Hacking Tools"
            },
            {
                "question": "What is the primary function of a backdoor in system hacking?",
                "options": [
                    "To provide remote access to the attacker",
                    "To exploit a specific vulnerability",
                    "To steal sensitive data from the system",
                    "To disable system defenses"
                ],
                "correctAnswer": 0,
                "category": "Exploitation Techniques"
            },
            {
                "question": "Which of the following is an example of a method used to hide tools and evade detection during system hacking?",
                "options": [
                    "Rootkits",
                    "Spyware",
                    "RATs (Remote Access Trojans)",
                    "Keyloggers"
                ],
                "correctAnswer": 0,
                "category": "Stealth & Evasion"
            },
            {
                "question": "What is the purpose of clearing logs during system hacking?",
                "options": [
                    "To gain unauthorized access to logs",
                    "To remove evidence of the attack",
                    "To prevent user login attempts",
                    "To disable the system"
                ],
                "correctAnswer": 1,
                "category": "Covering Tracks"
            },
            {
                "question": "Which of the following is a method used to hide malicious tools on a system during hacking?",
                "options": [
                    "Steganography",
                    "Port scanning",
                    "Phishing",
                    "SQL Injection"
                ],
                "correctAnswer": 0,
                "category": "Stealth & Evasion"
            },
            {
                "question": "Which of the following is used to execute a command on a target system remotely after gaining unauthorized access?",
                "options": [
                    "SSH tunneling",
                    "Backdoor",
                    "Password cracking",
                    "Port scanning"
                ],
                "correctAnswer": 1,
                "category": "Exploitation Techniques"
            },
            {
                "question": "Which of the following techniques is used to exploit a buffer overflow vulnerability?",
                "options": [
                    "SQL injection",
                    "Code injection",
                    "Shellcode",
                    "Password cracking"
                ],
                "correctAnswer": 2,
                "category": "Exploitation Techniques"
            },
            {
                "question": "Which of the following is a common type of system manipulation after compromising a target?",
                "options": [
                    "Spyware installation",
                    "Data exfiltration",
                    "Privilege escalation",
                    "Data wiping"
                ],
                "correctAnswer": 2,
                "category": "Post-Exploitation"
            },
            {
                "question": "Which of the following is a key characteristic of a rootkit?",
                "options": [
                    "It is used to maintain access to a system",
                    "It targets a specific user’s credentials",
                    "It operates only during a specific time window",
                    "It is visible to security software"
                ],
                "correctAnswer": 0,
                "category": "Stealth & Evasion"
            },
            {
                "question": "Which of the following is an example of a privilege escalation method in a Linux environment?",
                "options": [
                    "Sudo abuse",
                    "Brute-force SSH",
                    "XSS exploitation",
                    "SQL injection"
                ],
                "correctAnswer": 0,
                "category": "Privilege Escalation"
            }
        ],
        icon: "fa-user-shield",
        color: "cybersecurity",
        difficulty: "Easy",
        participants: 6,
        description: "Test your knowledge of basic cybersecurity concepts."
    },
    "CEH Lesson 7": {
        questions: [
            {
                "question": "Which of the following is a type of malware that hides its presence by modifying system files?",
                "options": [
                    "Virus",
                    "Trojan",
                    "Rootkit",
                    "Worm"
                ],
                "correctAnswer": 2,
                "category": "Malware Types"
            },
            {
                "question": "Which of the following malware types is designed to replicate itself and spread without user intervention?",
                "options": [
                    "Trojan",
                    "Virus",
                    "Worm",
                    "Spyware"
                ],
                "correctAnswer": 2,
                "category": "Malware Types"
            },
            {
                "question": "Which of the following malware types is typically spread via email attachments or downloads?",
                "options": [
                    "Virus",
                    "Worm",
                    "Spyware",
                    "Ransomware"
                ],
                "correctAnswer": 0,
                "category": "Malware Types"
            },
            {
                "question": "Which of the following is a key characteristic of ransomware?",
                "options": [
                    "It locks files and demands a ransom for decryption",
                    "It spreads across networks without user interaction",
                    "It is designed to collect sensitive data",
                    "It modifies system files to hide itself"
                ],
                "correctAnswer": 0,
                "category": "Malware Types"
            },
            {
                "question": "Which of the following malware types is used to monitor and record user activity without their consent?",
                "options": [
                    "Spyware",
                    "Trojan",
                    "Virus",
                    "Worm"
                ],
                "correctAnswer": 0,
                "category": "Malware Types"
            },
            {
                "question": "Which malware type is often delivered as a fake update or legitimate-looking file?",
                "options": [
                    "Trojan",
                    "Rootkit",
                    "Spyware",
                    "Worm"
                ],
                "correctAnswer": 0,
                "category": "Malware Types"
            },
            {
                "question": "Which malware type is used to exploit the flaws in the DNS protocol to redirect traffic?",
                "options": [
                    "DNS Spoofing",
                    "Trojan",
                    "Spyware",
                    "Rootkit"
                ],
                "correctAnswer": 0,
                "category": "Malware Types"
            },
            {
                "question": "Which of the following is a primary method of protecting against malware infections?",
                "options": [
                    "Installing antivirus software",
                    "Using weak passwords",
                    "Disabling firewalls",
                    "Allowing all incoming traffic"
                ],
                "correctAnswer": 0,
                "category": "Malware Defense"
            },
            {
                "question": "Which of the following techniques can be used by malware to avoid detection?",
                "options": [
                    "Code obfuscation",
                    "Encryption",
                    "Rootkit installation",
                    "All of the above"
                ],
                "correctAnswer": 3,
                "category": "Malware Evasion"
            },
            {
                "question": "Which of the following is a common delivery method for malware?",
                "options": [
                    "Email attachments",
                    "Removable USB drives",
                    "Network shares",
                    "All of the above"
                ],
                "correctAnswer": 3,
                "category": "Malware Delivery"
            },
            {
                "question": "What is a common characteristic of a Trojan?",
                "options": [
                    "It replicates itself",
                    "It locks files and demands a ransom",
                    "It pretends to be legitimate software to gain unauthorized access",
                    "It spreads through network protocols"
                ],
                "correctAnswer": 2,
                "category": "Malware Types"
            },
            {
                "question": "Which of the following tools is commonly used to analyze malware behavior?",
                "options": [
                    "Wireshark",
                    "John the Ripper",
                    "Cuckoo Sandbox",
                    "Metasploit"
                ],
                "correctAnswer": 2,
                "category": "Malware Analysis Tools"
            },
            {
                "question": "Which of the following is the most common method to deliver ransomware?",
                "options": [
                    "Email phishing links",
                    "Social media links",
                    "USB infection",
                    "Network vulnerabilities"
                ],
                "correctAnswer": 0,
                "category": "Ransomware Delivery"
            }
        ],
        icon: "fa-user-shield",
        color: "cybersecurity",
        difficulty: "Easy",
        participants: 6,
        description: "Test your knowledge of basic cybersecurity concepts."
    },
    "CEH Lesson 8": {
        questions: [
            {
                "question": "What is packet sniffing?",
                "options": [
                    "Intercepting and analyzing network traffic",
                    "Scanning ports on a network",
                    "Injecting malicious traffic into a network",
                    "Monitoring system logs"
                ],
                "correctAnswer": 0,
                "category": "Sniffing Basics"
            },
            {
                "question": "Which of the following is the most common protocol for sniffing unencrypted network traffic?",
                "options": [
                    "HTTP",
                    "FTP",
                    "Telnet",
                    "HTTPS"
                ],
                "correctAnswer": 0,
                "category": "Sniffing Protocols"
            },
            {
                "question": "Which of the following is an example of a passive sniffing technique?",
                "options": [
                    "Man-in-the-middle attack",
                    "ARP poisoning",
                    "Network traffic capture on a hub",
                    "DNS Spoofing"
                ],
                "correctAnswer": 2,
                "category": "Sniffing Techniques"
            },
            {
                "question": "Which of the following tools is used for packet sniffing?",
                "options": [
                    "Metasploit",
                    "Wireshark",
                    "John the Ripper",
                    "Burp Suite"
                ],
                "correctAnswer": 1,
                "category": "Sniffing Tools"
            },
            {
                "question": "Which sniffing attack involves intercepting and modifying network packets?",
                "options": [
                    "ARP Spoofing",
                    "DNS Spoofing",
                    "Session Hijacking",
                    "Man-in-the-Middle Attack"
                ],
                "correctAnswer": 3,
                "category": "Sniffing Attacks"
            },
            {
                "question": "What is the primary danger of sniffing unencrypted network traffic?",
                "options": [
                    "Stealing passwords and other sensitive data",
                    "Injecting malware into traffic",
                    "Disrupting the network connection",
                    "Spoofing network identity"
                ],
                "correctAnswer": 0,
                "category": "Sniffing Risks"
            },
            {
                "question": "Which of the following is a common method for sniffing network traffic in a switched environment?",
                "options": [
                    "Flooding the switch with traffic",
                    "ARP poisoning",
                    "Using a network tap",
                    "Flooding DNS requests"
                ],
                "correctAnswer": 1,
                "category": "Advanced Sniffing"
            },
            {
                "question": "What does ARP poisoning enable an attacker to do?",
                "options": [
                    "Redirect network traffic to the attacker’s machine",
                    "Steal session cookies",
                    "Capture DNS traffic",
                    "Decrypt encrypted traffic"
                ],
                "correctAnswer": 0,
                "category": "ARP Poisoning"
            },
            {
                "question": "Which of the following is a tool used for sniffing Wi-Fi traffic?",
                "options": [
                    "Wireshark",
                    "Aircrack-ng",
                    "Tcpdump",
                    "Nessus"
                ],
                "correctAnswer": 1,
                "category": "Sniffing Tools"
            },
            {
                "question": "What is the primary purpose of a Session Hijacking attack?",
                "options": [
                    "To intercept session cookies",
                    "To steal login credentials",
                    "To inject malicious content into a session",
                    "To take control of an active session"
                ],
                "correctAnswer": 3,
                "category": "Session Hijacking"
            },
            {
                "question": "Which of the following techniques is used to bypass network security and sniff encrypted traffic?",
                "options": [
                    "Brute Force",
                    "SSL Stripping",
                    "DNS Spoofing",
                    "TCP Reset Attack"
                ],
                "correctAnswer": 1,
                "category": "Sniffing Techniques"
            },
            {
                "question": "What is the purpose of sniffing on a network?",
                "options": [
                    "To monitor traffic and gain sensitive information",
                    "To monitor network performance",
                    "To scan for open ports",
                    "To prevent unauthorized access"
                ],
                "correctAnswer": 0,
                "category": "Sniffing Basics"
            },
            {
                "question": "Which of the following protocols is secure against sniffing attacks due to its encryption?",
                "options": [
                    "FTP",
                    "HTTP",
                    "HTTPS",
                    "Telnet"
                ],
                "correctAnswer": 2,
                "category": "Sniffing Protocols"
            },
            {
                "question": "Which type of sniffing attack allows an attacker to inject malicious data into network traffic?",
                "options": [
                    "Man-in-the-Middle Attack",
                    "Session Hijacking",
                    "ARP Spoofing",
                    "DNS Spoofing"
                ],
                "correctAnswer": 0,
                "category": "Sniffing Attacks"
            }
        ],
        icon: "fa-user-shield",
        color: "cybersecurity",
        difficulty: "Easy",
        participants: 6,
        description: "Test your knowledge of basic cybersecurity concepts."
    },
    "CEH Lesson 9": {
        questions: [
            {
                "question": "What is the primary objective of social engineering attacks?",
                "options": [
                    "To exploit technical vulnerabilities in a system",
                    "To manipulate individuals into revealing sensitive information",
                    "To steal passwords using brute-force attacks",
                    "To perform denial-of-service attacks"
                ],
                "correctAnswer": 1,
                "category": "Social Engineering Basics"
            },
            {
                "question": "Which of the following is an example of phishing?",
                "options": [
                    "Sending an email that appears to be from a legitimate source to steal personal information",
                    "A hacker exploiting a weakness in a website's login page",
                    "An attacker installing malware on a victim's computer via a USB drive",
                    "An attacker intercepting unencrypted network traffic"
                ],
                "correctAnswer": 0,
                "category": "Phishing"
            },
            {
                "question": "Which of the following is a key tactic used in pretexting?",
                "options": [
                    "Creating a fake story or identity to gain trust",
                    "Sending a fake link via email to steal login credentials",
                    "Manipulating someone to gain physical access to a building",
                    "Impersonating a legitimate service for malicious purposes"
                ],
                "correctAnswer": 0,
                "category": "Pretexting"
            },
            {
                "question": "Which of the following is an example of tailgating?",
                "options": [
                    "Gaining unauthorized access to a building by following an authorized person",
                    "Sending fake emails to gain confidential information",
                    "Installing malware via email attachments",
                    "Using social media to gather information for attacks"
                ],
                "correctAnswer": 0,
                "category": "Physical Social Engineering"
            },
            {
                "question": "Which of the following is a technique used in baiting attacks?",
                "options": [
                    "Offering something enticing to get the victim to click on a malicious link",
                    "Tricking victims into sharing confidential information via fake websites",
                    "Gaining physical access to a system by pretending to be a technician",
                    "Manipulating someone into clicking on an attachment in an email"
                ],
                "correctAnswer": 0,
                "category": "Baiting"
            },
            {
                "question": "What is the term for exploiting social relationships to manipulate someone into revealing confidential information?",
                "options": [
                    "Pretexting",
                    "Phishing",
                    "Baiting",
                    "Social engineering"
                ],
                "correctAnswer": 3,
                "category": "Social Engineering Techniques"
            },
            {
                "question": "Which of the following is the best defense against phishing attacks?",
                "options": [
                    "Using multi-factor authentication",
                    "Monitoring network traffic",
                    "Performing regular penetration testing",
                    "Enabling firewalls"
                ],
                "correctAnswer": 0,
                "category": "Phishing Countermeasures"
            },
            {
                "question": "Which of the following social engineering attacks involves exploiting a person’s fear to obtain information?",
                "options": [
                    "Phishing",
                    "Pretexting",
                    "Baiting",
                    "Impersonation"
                ],
                "correctAnswer": 1,
                "category": "Psychology of Social Engineering"
            },
            {
                "question": "Which of the following is NOT a method of preventing social engineering attacks?",
                "options": [
                    "Employee training and awareness",
                    "Multi-factor authentication",
                    "Disabling unused network ports",
                    "Regular patching of vulnerabilities"
                ],
                "correctAnswer": 3,
                "category": "Defense Against Social Engineering"
            },
            {
                "question": "What is the primary method attackers use to gather information during a social engineering attack?",
                "options": [
                    "Port scanning",
                    "Social media and public sources",
                    "Network traffic analysis",
                    "Malware installation"
                ],
                "correctAnswer": 1,
                "category": "Social Engineering Information Gathering"
            },
            {
                "question": "Which of the following is an example of a reverse social engineering attack?",
                "options": [
                    "Tricking a victim into calling the attacker’s phone number for support",
                    "Sending an email pretending to be from a bank to steal credentials",
                    "Using social media to impersonate a victim",
                    "Tricking an employee into sharing sensitive company data"
                ],
                "correctAnswer": 0,
                "category": "Reverse Social Engineering"
            },
            {
                "question": "What is the best way to defend against social engineering attacks?",
                "options": [
                    "Security policies and procedures",
                    "Employee training and awareness programs",
                    "Regular penetration testing",
                    "Secure the physical network with firewalls"
                ],
                "correctAnswer": 1,
                "category": "Defense Strategies"
            },
            {
                "question": "Which of the following is a sign of an insider threat?",
                "options": [
                    "Unusual access patterns",
                    "Lack of physical security",
                    "Network anomalies",
                    "Weak passwords"
                ],
                "correctAnswer": 0,
                "category": "Insider Threats"
            }
        ],
        icon: "fa-user-shield",
        color: "cybersecurity",
        difficulty: "Easy",
        participants: 6,
        description: "Test your knowledge of basic cybersecurity concepts."
    },
    "CEH Lesson 10": {
        questions: [
            {
                "question": "What is the main goal of a Denial-of-Service (DoS) attack?",
                "options": [
                    "To gain unauthorized access to a system",
                    "To disrupt the availability of a network or service",
                    "To steal sensitive information",
                    "To bypass authentication"
                ],
                "correctAnswer": 1,
                "category": "DoS/DDoS Basics"
            },
            {
                "question": "What is a Distributed Denial-of-Service (DDoS) attack?",
                "options": [
                    "A DoS attack that uses a single source",
                    "A DoS attack that uses multiple distributed sources",
                    "An attack that targets the DNS servers",
                    "A form of phishing attack"
                ],
                "correctAnswer": 1,
                "category": "DoS/DDoS Types"
            },
            {
                "question": "Which of the following is a common attack vector for DDoS attacks?",
                "options": [
                    "UDP floods",
                    "DNS Spoofing",
                    "SQL Injection",
                    "Cross-Site Scripting"
                ],
                "correctAnswer": 0,
                "category": "DDoS Attack Vectors"
            },
            {
                "question": "Which of the following best describes a botnet in a DDoS attack?",
                "options": [
                    "A group of compromised computers controlled by an attacker",
                    "A network used to securely transmit data",
                    "A method to hide attack traffic",
                    "A type of firewall used to block attacks"
                ],
                "correctAnswer": 0,
                "category": "DDoS Botnet"
            },
            {
                "question": "Which of the following is a tool commonly used to launch DDoS attacks?",
                "options": [
                    "LOIC (Low Orbit Ion Cannon)",
                    "Metasploit",
                    "Wireshark",
                    "Burp Suite"
                ],
                "correctAnswer": 0,
                "category": "DDoS Tools"
            },
            {
                "question": "What is the primary difference between a volumetric DDoS attack and a protocol-based DDoS attack?",
                "options": [
                    "Volumetric attacks focus on overwhelming bandwidth, while protocol-based attacks exploit protocol flaws",
                    "Volumetric attacks focus on exploiting DNS, while protocol-based attacks target UDP",
                    "Volumetric attacks use fewer devices, while protocol-based attacks use more",
                    "There is no difference"
                ],
                "correctAnswer": 0,
                "category": "DDoS Attack Types"
            },
            {
                "question": "Which DDoS attack type exploits weaknesses in a network protocol by flooding the target with malformed packets?",
                "options": [
                    "SYN Flood",
                    "Ping of Death",
                    "UDP Flood",
                    "HTTP Flood"
                ],
                "correctAnswer": 1,
                "category": "DDoS Attack Types"
            },
            {
                "question": "Which of the following is an amplification technique used in DDoS attacks?",
                "options": [
                    "DNS Reflection",
                    "ARP Poisoning",
                    "SQL Injection",
                    "Cross-Site Request Forgery"
                ],
                "correctAnswer": 0,
                "category": "DDoS Amplification"
            },
            {
                "question": "Which of the following is a commonly used method to mitigate DDoS attacks?",
                "options": [
                    "Rate limiting",
                    "Using weak passwords",
                    "Installing antivirus software",
                    "Disabling firewalls"
                ],
                "correctAnswer": 0,
                "category": "DDoS Mitigation"
            },
            {
                "question": "Which of the following services provides DDoS protection for websites?",
                "options": [
                    "Cloudflare",
                    "OpenVPN",
                    "Tor",
                    "Wireshark"
                ],
                "correctAnswer": 0,
                "category": "DDoS Mitigation"
            },
            {
                "question": "What is the purpose of a stresser/booter service in a DDoS attack?",
                "options": [
                    "To bypass a firewall",
                    "To provide a legitimate source for attack traffic",
                    "To test a DDoS attack in a controlled environment",
                    "To execute a payload on a compromised machine"
                ],
                "correctAnswer": 1,
                "category": "DDoS Attack Techniques"
            },
            {
                "question": "Which of the following DDoS attack types targets the application layer?",
                "options": [
                    "HTTP Flood",
                    "UDP Flood",
                    "SYN Flood",
                    "ICMP Flood"
                ],
                "correctAnswer": 0,
                "category": "Application Layer DDoS"
            },
            {
                "question": "What is the best way to detect DDoS traffic?",
                "options": [
                    "Monitoring traffic patterns for anomalies",
                    "Disabling firewalls",
                    "Using port scanning tools",
                    "Running a vulnerability scan"
                ],
                "correctAnswer": 0,
                "category": "DDoS Detection"
            },
            {
                "question": "Which of the following cloud-based services helps protect against DDoS attacks?",
                "options": [
                    "Cloudflare",
                    "AWS Shield",
                    "Azure Security Center",
                    "All of the above"
                ],
                "correctAnswer": 3,
                "category": "DDoS Mitigation"
            },
            {
                "question": "What is the most common consequence of a DDoS attack?",
                "options": [
                    "Loss of data integrity",
                    "Website downtime or service disruption",
                    "Stolen credentials",
                    "Access to private information"
                ],
                "correctAnswer": 1,
                "category": "DDoS Consequences"
            }
        ],
        icon: "fa-user-shield",
        color: "cybersecurity",
        difficulty: "Easy",
        participants: 6,
        description: "Test your knowledge of basic cybersecurity concepts."
    },
    "CEH Lesson 11": {
        questions: [
            {
                "question": "What is the main goal of a session hijacking attack?",
                "options": [
                    "To intercept and take control of an active user session",
                    "To flood a target system with requests",
                    "To steal sensitive data from a target system",
                    "To exploit system vulnerabilities"
                ],
                "correctAnswer": 0,
                "category": "Session Hijacking Basics"
            },
            {
                "question": "Which of the following is a common target of session hijacking attacks?",
                "options": [
                    "User cookies",
                    "Usernames and passwords",
                    "Operating system vulnerabilities",
                    "Network protocols"
                ],
                "correctAnswer": 0,
                "category": "Session Hijacking"
            },
            {
                "question": "What type of session hijacking attack involves predicting the sequence number of a TCP connection?",
                "options": [
                    "Session Fixation",
                    "Session Stealing",
                    "TCP Session Hijacking",
                    "Cross-Site Request Forgery"
                ],
                "correctAnswer": 2,
                "category": "Session Hijacking Techniques"
            },
            {
                "question": "Which of the following is a technique used in TCP session hijacking?",
                "options": [
                    "Sequence number prediction",
                    "DNS poisoning",
                    "Cross-Site Scripting",
                    "Buffer overflow"
                ],
                "correctAnswer": 0,
                "category": "Session Hijacking Techniques"
            },
            {
                "question": "Which of the following attacks is used to intercept a session token?",
                "options": [
                    "Phishing",
                    "Man-in-the-Middle",
                    "DNS Spoofing",
                    "SQL Injection"
                ],
                "correctAnswer": 1,
                "category": "Session Hijacking Techniques"
            },
            {
                "question": "Which of the following tools can be used to hijack sessions during a Man-in-the-Middle (MITM) attack?",
                "options": [
                    "Wireshark",
                    "Metasploit",
                    "Cain and Abel",
                    "John the Ripper"
                ],
                "correctAnswer": 1,
                "category": "Session Hijacking Tools"
            },
            {
                "question": "Which of the following is an effective way to prevent session hijacking?",
                "options": [
                    "Using secure cookies with the 'Secure' and 'HttpOnly' flags",
                    "Using only weak encryption for session tokens",
                    "Storing session data on the client-side",
                    "Using static IP addresses for session authentication"
                ],
                "correctAnswer": 0,
                "category": "Countermeasures"
            },
            {
                "question": "Which of the following session management techniques helps mitigate session hijacking?",
                "options": [
                    "Session timeouts and re-authentication",
                    "Storing session data in cookies",
                    "Using unencrypted session tokens",
                    "Allowing session reuse"
                ],
                "correctAnswer": 0,
                "category": "Countermeasures"
            },
            {
                "question": "Which of the following is used in session fixation attacks to set a valid session ID before a user authenticates?",
                "options": [
                    "Session hijacking",
                    "Malware",
                    "Spoofing",
                    "Phishing"
                ],
                "correctAnswer": 2,
                "category": "Session Fixation"
            },
            {
                "question": "Which type of attack is prevented by using Multi-Factor Authentication (MFA)?",
                "options": [
                    "Session Hijacking",
                    "Phishing",
                    "SQL Injection",
                    "Cross-Site Request Forgery"
                ],
                "correctAnswer": 0,
                "category": "Session Hijacking Prevention"
            },
            {
                "question": "Which of the following can be used to detect session hijacking attempts?",
                "options": [
                    "Session logging and monitoring",
                    "Encryption of session tokens",
                    "Session token expiry",
                    "All of the above"
                ],
                "correctAnswer": 3,
                "category": "Session Hijacking Detection"
            },
            {
                "question": "Which of the following protocols can be vulnerable to session hijacking attacks?",
                "options": [
                    "HTTP",
                    "HTTPS",
                    "FTP",
                    "All of the above"
                ],
                "correctAnswer": 0,
                "category": "Session Hijacking"
            }
        ],
        icon: "fa-user-shield",
        color: "cybersecurity",
        difficulty: "Easy",
        participants: 6,
        description: "Test your knowledge of basic cybersecurity concepts."
    },
    "CEH Lesson 12": {
        questions: [
            {
                "question": "What is the primary purpose of an Intrusion Detection System (IDS)?",
                "options": [
                    "To prevent unauthorized access to a network",
                    "To detect and alert on suspicious network activity",
                    "To create firewall rules",
                    "To encrypt network traffic"
                ],
                "correctAnswer": 1,
                "category": "IDS/IPS Basics"
            },
            {
                "question": "What is the key difference between an IDS and an IPS?",
                "options": [
                    "IDS detects and responds to attacks, while IPS only detects",
                    "IDS is proactive, while IPS is reactive",
                    "IPS detects and prevents attacks, while IDS only detects",
                    "IDS encrypts network traffic, while IPS blocks traffic"
                ],
                "correctAnswer": 2,
                "category": "IDS/IPS Basics"
            },
            {
                "question": "Which of the following is a common technique used to evade an IDS or IPS?",
                "options": [
                    "Packet fragmentation",
                    "Port forwarding",
                    "Encryption of session tokens",
                    "Use of multi-factor authentication"
                ],
                "correctAnswer": 0,
                "category": "Evasion Techniques"
            },
            {
                "question": "Which of the following is a common method used to evade firewalls?",
                "options": [
                    "IP Spoofing",
                    "Session Hijacking",
                    "Phishing",
                    "Social Engineering"
                ],
                "correctAnswer": 0,
                "category": "Firewall Evasion"
            },
            {
                "question": "Which of the following is a tool that can be used for IDS evasion?",
                "options": [
                    "Nmap",
                    "Metasploit",
                    "Hping",
                    "Wireshark"
                ],
                "correctAnswer": 2,
                "category": "IDS/IPS Tools"
            },
            {
                "question": "Which of the following IDS/IPS evasion methods involves splitting packets into smaller parts?",
                "options": [
                    "IP Spoofing",
                    "Packet fragmentation",
                    "Session hijacking",
                    "Denial of Service"
                ],
                "correctAnswer": 1,
                "category": "Evasion Techniques"
            },
            {
                "question": "What is a honeypot in cybersecurity?",
                "options": [
                    "A tool used to monitor network traffic",
                    "A decoy system set up to attract and study attackers",
                    "A device used to encrypt sensitive data",
                    "A method of patching vulnerabilities"
                ],
                "correctAnswer": 1,
                "category": "Honeypots"
            },
            {
                "question": "Which of the following is a common IDS/IPS detection technique?",
                "options": [
                    "Signature-based detection",
                    "DNS filtering",
                    "TCP/IP Spoofing",
                    "Port scanning"
                ],
                "correctAnswer": 0,
                "category": "IDS/IPS Detection Techniques"
            },
            {
                "question": "What is the role of a firewall in a network security architecture?",
                "options": [
                    "To detect malware and viruses",
                    "To monitor network traffic and prevent unauthorized access",
                    "To monitor for phishing attacks",
                    "To enforce password policies"
                ],
                "correctAnswer": 1,
                "category": "Firewall Basics"
            },
            {
                "question": "Which of the following is a key advantage of using a web application firewall (WAF)?",
                "options": [
                    "It provides encryption for all traffic",
                    "It prevents DDoS attacks",
                    "It filters and monitors HTTP requests",
                    "It creates a VPN for secure communication"
                ],
                "correctAnswer": 2,
                "category": "Firewall Evasion"
            },
            {
                "question": "What does Deep Packet Inspection (DPI) in a firewall do?",
                "options": [
                    "Analyzes the content of the packet, including headers and data",
                    "Blocks all inbound traffic",
                    "Encrypts outgoing traffic",
                    "Performs packet fragmentation"
                ],
                "correctAnswer": 0,
                "category": "Firewall Techniques"
            },
            {
                "question": "Which of the following techniques is used by attackers to hide malicious activity from intrusion detection systems?",
                "options": [
                    "Packet fragmentation",
                    "Session hijacking",
                    "IP Spoofing",
                    "Data exfiltration"
                ],
                "correctAnswer": 0,
                "category": "IDS/IPS Evasion"
            },
            {
                "question": "What is the purpose of an anomaly-based IDS?",
                "options": [
                    "To detect known attack signatures",
                    "To detect unusual network traffic patterns that deviate from baseline behavior",
                    "To block malicious IP addresses",
                    "To prevent DDoS attacks"
                ],
                "correctAnswer": 1,
                "category": "IDS/IPS Techniques"
            }
        ],
        icon: "fa-user-shield",
        color: "cybersecurity",
        difficulty: "Easy",
        participants: 6,
        description: "Test your knowledge of basic cybersecurity concepts."
    },
    "CEH Lesson 13": {
        questions: [
            {
                "question": "Which of the following is a common attack vector for compromising web servers?",
                "options": [
                    "SQL Injection",
                    "Buffer Overflow",
                    "Cross-Site Scripting (XSS)",
                    "All of the above"
                ],
                "correctAnswer": 3,
                "category": "Web Server Attack Vectors"
            },
            {
                "question": "Which web server software is commonly targeted in attacks due to misconfigurations?",
                "options": [
                    "Apache",
                    "Nginx",
                    "IIS",
                    "All of the above"
                ],
                "correctAnswer": 3,
                "category": "Web Server Attacks"
            },
            {
                "question": "What is the primary purpose of a web application firewall (WAF)?",
                "options": [
                    "To filter and monitor HTTP traffic to and from a web application",
                    "To encrypt web traffic",
                    "To monitor network traffic for intrusions",
                    "To perform patch management on the server"
                ],
                "correctAnswer": 0,
                "category": "Web Server Defense"
            },
            {
                "question": "Which of the following attacks targets web servers by sending malicious HTTP requests?",
                "options": [
                    "Cross-Site Scripting (XSS)",
                    "Denial-of-Service (DoS)",
                    "SQL Injection",
                    "HTTP Flood"
                ],
                "correctAnswer": 3,
                "category": "Web Server Attacks"
            },
            {
                "question": "What is a directory traversal attack?",
                "options": [
                    "Exploiting a vulnerability to access files and directories outside the web server's root directory",
                    "A DDoS attack targeting web servers",
                    "Using web shells to execute commands remotely",
                    "Injecting malicious SQL queries into a web application"
                ],
                "correctAnswer": 0,
                "category": "Web Server Vulnerabilities"
            },
            {
                "question": "Which of the following methods is commonly used to exploit web server vulnerabilities?",
                "options": [
                    "Buffer Overflow",
                    "SQL Injection",
                    "Web Shells",
                    "All of the above"
                ],
                "correctAnswer": 3,
                "category": "Web Server Exploits"
            },
            {
                "question": "Which type of attack is often associated with exploiting weak SSH configurations on a web server?",
                "options": [
                    "Brute-force Attack",
                    "Man-in-the-Middle Attack",
                    "Cross-Site Request Forgery",
                    "Cross-Site Scripting"
                ],
                "correctAnswer": 0,
                "category": "Web Server Security"
            },
            {
                "question": "What is the purpose of a web shell on a compromised web server?",
                "options": [
                    "To execute malicious commands remotely on the server",
                    "To monitor server performance",
                    "To prevent access to the server",
                    "To encrypt data on the server"
                ],
                "correctAnswer": 0,
                "category": "Web Server Attacks"
            },
            {
                "question": "Which of the following is an example of a server misconfiguration that could lead to a web server attack?",
                "options": [
                    "Weak file permissions",
                    "Unpatched software",
                    "Exposed admin interfaces",
                    "All of the above"
                ],
                "correctAnswer": 3,
                "category": "Web Server Security Misconfigurations"
            },
            {
                "question": "Which of the following is a critical defense against web server attacks?",
                "options": [
                    "Patching software vulnerabilities",
                    "Using strong passwords for admin accounts",
                    "Disabling unused services",
                    "All of the above"
                ],
                "correctAnswer": 3,
                "category": "Web Server Security"
            },
            {
                "question": "Which of the following tools can be used to scan web servers for vulnerabilities?",
                "options": [
                    "Burp Suite",
                    "Nessus",
                    "Nikto",
                    "All of the above"
                ],
                "correctAnswer": 3,
                "category": "Web Server Security Tools"
            },
            {
                "question": "Which of the following is a common vulnerability in web applications that can lead to server compromise?",
                "options": [
                    "Cross-Site Scripting (XSS)",
                    "SQL Injection",
                    "Command Injection",
                    "All of the above"
                ],
                "correctAnswer": 3,
                "category": "Web Application Vulnerabilities"
            },
            {
                "question": "Which of the following protocols is commonly exploited for attacks targeting web servers?",
                "options": [
                    "HTTP",
                    "HTTPS",
                    "FTP",
                    "SSH"
                ],
                "correctAnswer": 0,
                "category": "Web Server Protocols"
            }
        ],
        icon: "fa-user-shield",
        color: "cybersecurity",
        difficulty: "Easy",
        participants: 6,
        description: "Test your knowledge of basic cybersecurity concepts."
    },
    "CEH Lesson 14": {
        questions: [
            {
                "question": "Which of the following is categorized as an OWASP Top 10 vulnerability?",
                "options": [
                    "LDAP Injection",
                    "Broken Access Control",
                    "ARP Spoofing",
                    "Buffer Overflow"
                ],
                "correctAnswer": 1,
                "category": "OWASP Top 10"
            },
            {
                "question": "What does SQL Injection (SQLi) target in a web application?",
                "options": [
                    "HTML forms only",
                    "Database queries generated from user input",
                    "Network protocols",
                    "Client-side scripts"
                ],
                "correctAnswer": 1,
                "category": "Injection"
            },
            {
                "question": "Which of the following best describes Cross-Site Scripting (XSS)?",
                "options": [
                    "Injecting SQL into a form field",
                    "Injecting malicious JavaScript into a web page viewed by others",
                    "Manipulating cookies via CSRF",
                    "Executing shell commands on the server"
                ],
                "correctAnswer": 1,
                "category": "XSS"
            },
            {
                "question": "What is the primary goal of Cross-Site Request Forgery (CSRF)?",
                "options": [
                    "Steal database credentials",
                    "Authorize unintended actions by a logged-in user",
                    "Perform network scanning",
                    "Exploit buffer overflows"
                ],
                "correctAnswer": 1,
                "category": "CSRF"
            },
            {
                "question": "Which of the following is a server-side vulnerability that allows an attacker to read or write files on the server?",
                "options": [
                    "Cross-Site Scripting",
                    "Local File Inclusion",
                    "SQL Injection",
                    "DNS Spoofing"
                ],
                "correctAnswer": 1,
                "category": "Server-Side Vulnerabilities"
            },
            {
                "question": "What is Insecure Direct Object Reference (IDOR)?",
                "options": [
                    "Use of predictable links to reference internal objects",
                    "Injection of malicious scripts into user input",
                    "Broken authentication method",
                    "Cross-Site Scripting variant"
                ],
                "correctAnswer": 0,
                "category": "Access Control"
            },
            {
                "question": "Which tool is commonly used for intercepting and modifying HTTP requests in web apps?",
                "options": [
                    "Wireshark",
                    "Burp Suite",
                    "Nmap",
                    "Metasploit"
                ],
                "correctAnswer": 1,
                "category": "Testing Tools"
            },
            {
                "question": "Which of the following methods mitigates SQL Injection in web applications?",
                "options": [
                    "Sanitizing user input and using parameterized queries",
                    "Disabling cookies",
                    "Obfuscating the database schema",
                    "Using client-side validation only"
                ],
                "correctAnswer": 0,
                "category": "Countermeasures"
            },
            {
                "question": "Which type of Cross-Site Scripting is stored on the server and permanently served to users?",
                "options": [
                    "Reflected XSS",
                    "Stored XSS",
                    "DOM-Based XSS",
                    "Blind XSS"
                ],
                "correctAnswer": 1,
                "category": "XSS"
            },
            {
                "question": "Which of the following is an example of a REST API vulnerability?",
                "options": [
                    "Cross-Site Request Forgery",
                    "NoSQL Injection",
                    "Buffer Overflow",
                    "ARP Poisoning"
                ],
                "correctAnswer": 1,
                "category": "API Vulnerabilities"
            },
            {
                "question": "What does Server-Side Request Forgery (SSRF) allow an attacker to do?",
                "options": [
                    "Execute JavaScript on the client",
                    "Force the server to make HTTP requests to arbitrary domains",
                    "Inject SQL into queries",
                    "Capture session cookies"
                ],
                "correctAnswer": 1,
                "category": "Advanced Vulnerabilities"
            },
            {
                "question": "Which practice helps prevent Insecure Direct Object References (IDOR)?",
                "options": [
                    "Using sequential numeric IDs in URLs",
                    "Validating and authorizing access to object references on the server",
                    "Relying solely on JavaScript checks",
                    "Encrypting cookies"
                ],
                "correctAnswer": 1,
                "category": "Countermeasures"
            },
            {
                "question": "Which of the following is a best practice for securing JSON Web Tokens (JWT) in web applications?",
                "options": [
                    "Store them in local storage without flags",
                    "Use `HttpOnly` and `Secure` cookie flags",
                    "Include sensitive data in the payload",
                    "Use a short, weak signing key"
                ],
                "correctAnswer": 1,
                "category": "Session Management"
            },
            {
                "question": "Which of the following counters Cross-Site Scripting (XSS) in web applications?",
                "options": [
                    "Input validation and output encoding",
                    "Disabling TLS",
                    "Using predictable session IDs",
                    "Hosting on shared servers"
                ],
                "correctAnswer": 0,
                "category": "Countermeasures"
            },
            {
                "question": "What is a common use of a web application firewall (WAF)?",
                "options": [
                    "Block SQL injection and cross-site scripting attacks",
                    "Manage DNS records",
                    "Monitor network performance",
                    "Encrypt data at rest"
                ],
                "correctAnswer": 0,
                "category": "Web Server Defense"
            }
        ],
        icon: "fa-user-shield",
        color: "cybersecurity",
        difficulty: "Easy",
        participants: 6,
        description: "Test your knowledge of basic cybersecurity concepts."
    },
    "CEH Lesson 15": {
        questions: [
            {
                "question": "What is the main goal of a SQL Injection (SQLi) attack?",
                "options": [
                    "To execute arbitrary JavaScript in a user’s browser",
                    "To manipulate database queries to view or modify data",
                    "To flood a server with HTTP requests",
                    "To exploit buffer overflow vulnerabilities"
                ],
                "correctAnswer": 1,
                "category": "SQLi Basics"
            },
            {
                "question": "Which of the following is an example of an error-based SQLi payload?",
                "options": [
                    "' OR '1'='1",
                    "'; DROP TABLE users;--",
                    "' UNION SELECT NULL, version()--",
                    "' OR SLEEP(5)--"
                ],
                "correctAnswer": 2,
                "category": "SQLi Techniques"
            },
            {
                "question": "Which type of SQLi attack allows an attacker to infer data based on true/false responses?",
                "options": [
                    "Error-based SQLi",
                    "Blind Boolean-based SQLi",
                    "Out-of-band SQLi",
                    "Time-based SQLi"
                ],
                "correctAnswer": 1,
                "category": "SQLi Techniques"
            },
            {
                "question": "Which of the following SQL commands can be used to perform a UNION-based SQL injection?",
                "options": [
                    "SELECT name FROM users WHERE id = '1' UNION SELECT username, password FROM admins--",
                    "UPDATE users SET password='password' WHERE id=1",
                    "DELETE FROM users WHERE id=1",
                    "INSERT INTO users (username) VALUES('admin')"
                ],
                "correctAnswer": 0,
                "category": "SQLi Techniques"
            },
            {
                "question": "Which type of SQLi exploits a delay function in the database to infer data?",
                "options": [
                    "Error-based SQLi",
                    "Blind Boolean-based SQLi",
                    "Time-based SQLi",
                    "Out-of-band SQLi"
                ],
                "correctAnswer": 2,
                "category": "SQLi Techniques"
            },
            {
                "question": "Which automated tool is commonly used to detect and exploit SQLi vulnerabilities?",
                "options": [
                    "Nmap",
                    "SQLMap",
                    "Metasploit",
                    "Wireshark"
                ],
                "correctAnswer": 1,
                "category": "SQLi Tools"
            },
            {
                "question": "What is the primary defense against SQL Injection?",
                "options": [
                    "Using parameterized queries or prepared statements",
                    "Disabling cookies",
                    "Using client-side validation only",
                    "Encrypting the database"
                ],
                "correctAnswer": 0,
                "category": "Countermeasures"
            },
            {
                "question": "Which of the following is an example of a blind SQLi payload?",
                "options": [
                    "' OR 1=1--",
                    "' AND (SELECT COUNT(*) FROM users WHERE username='admin') > 0--",
                    "'; DROP TABLE users;--",
                    "' OR SLEEP(10)--"
                ],
                "correctAnswer": 1,
                "category": "SQLi Techniques"
            },
            {
                "question": "Which database function can be abused in SQLi to execute operating system commands on SQL Server?",
                "options": [
                    "xp_cmdshell",
                    "SLEEP",
                    "LOAD_FILE",
                    "BENCHMARK"
                ],
                "correctAnswer": 0,
                "category": "Advanced SQLi"
            },
            {
                "question": "Which type of SQLi involves using external channels, such as DNS or HTTP, to retrieve data?",
                "options": [
                    "Error-based SQLi",
                    "Blind Boolean-based SQLi",
                    "Time-based SQLi",
                    "Out-of-band (OOB) SQLi"
                ],
                "correctAnswer": 3,
                "category": "SQLi Techniques"
            },
            {
                "question": "Which of the following is a recommended practice to prevent SQLi in web applications?",
                "options": [
                    "Validate and sanitize user input",
                    "Use dynamic SQL queries",
                    "Allow direct user-supplied SQL to execute",
                    "Disable database logging"
                ],
                "correctAnswer": 0,
                "category": "Countermeasures"
            },
            {
                "question": "Which database feature can help limit the impact of SQL injection by restricting user permissions?",
                "options": [
                    "Least privilege principle for database accounts",
                    "Enabling stored procedures",
                    "Disabling prepared statements",
                    "Encrypting the database schema"
                ],
                "correctAnswer": 0,
                "category": "Countermeasures"
            },
            {
                "question": "Which of the following payloads attempts to test for SQLi via a timing delay?",
                "options": [
                    "' OR 1=1--",
                    "' AND SLEEP(5)--",
                    "' UNION SELECT username, password FROM users--",
                    "'; DROP DATABASE--"
                ],
                "correctAnswer": 1,
                "category": "SQLi Techniques"
            },
            {
                "question": "What is a primary symptom of a successful SQL Injection attack in error-based exploitation?",
                "options": [
                    "Database returns an SQL error message revealing structure",
                    "Application logs out users",
                    "Network traffic is flooded",
                    "Page reloads without change"
                ],
                "correctAnswer": 0,
                "category": "SQLi Detection"
            }
        ],
        icon: "fa-user-shield",
        color: "cybersecurity",
        difficulty: "Easy",
        participants: 6,
        description: "Test your knowledge of basic cybersecurity concepts."
    },
    "CEH Lesson 16": {
        questions: [
            {
                "question": "Which of the following wireless encryption protocols is considered the least secure?",
                "options": [
                    "WEP",
                    "WPA2",
                    "WPA3",
                    "TLS"
                ],
                "correctAnswer": 0,
                "category": "Wireless Encryption"
            },
            {
                "question": "What type of attack involves an attacker setting up a rogue access point that mimics a legitimate access point?",
                "options": [
                    "Man-in-the-Middle Attack",
                    "Evil Twin Attack",
                    "Denial-of-Service Attack",
                    "WEP Cracking"
                ],
                "correctAnswer": 1,
                "category": "Wireless Security Attacks"
            },
            {
                "question": "Which of the following Wi-Fi security protocols is the most secure?",
                "options": [
                    "WEP",
                    "WPA",
                    "WPA2",
                    "WPA3"
                ],
                "correctAnswer": 3,
                "category": "Wireless Security Protocols"
            },
            {
                "question": "Which of the following tools is commonly used to crack WEP encryption on wireless networks?",
                "options": [
                    "Aircrack-ng",
                    "Wireshark",
                    "Metasploit",
                    "Nmap"
                ],
                "correctAnswer": 0,
                "category": "Wi-Fi Cracking Tools"
            },
            {
                "question": "What is the primary weakness of WEP encryption?",
                "options": [
                    "Weak initialization vectors (IVs)",
                    "Lack of authentication",
                    "Weak passwords",
                    "No encryption"
                ],
                "correctAnswer": 0,
                "category": "WEP Weaknesses"
            },
            {
                "question": "Which of the following attacks involves intercepting Wi-Fi communication to inject malicious data into the network?",
                "options": [
                    "Session Hijacking",
                    "Packet Injection",
                    "Man-in-the-Middle Attack",
                    "DNS Spoofing"
                ],
                "correctAnswer": 1,
                "category": "Wireless Attacks"
            },
            {
                "question": "What is the purpose of a wireless IDS/IPS in a wireless network?",
                "options": [
                    "To prevent unauthorized access to the network",
                    "To block specific IP addresses",
                    "To detect and respond to malicious activities",
                    "To provide strong encryption"
                ],
                "correctAnswer": 2,
                "category": "Wireless IDS/IPS"
            },
            {
                "question": "Which of the following tools is used to monitor wireless networks and capture packets?",
                "options": [
                    "Wireshark",
                    "Metasploit",
                    "Kismet",
                    "Aircrack-ng"
                ],
                "correctAnswer": 2,
                "category": "Wireless Monitoring Tools"
            },
            {
                "question": "Which of the following is a recommended method for securing Wi-Fi networks?",
                "options": [
                    "Using WPA3 encryption",
                    "Using WEP encryption",
                    "Using the default SSID",
                    "Disabling encryption"
                ],
                "correctAnswer": 0,
                "category": "Wi-Fi Security Best Practices"
            },
            {
                "question": "What is the main risk of using public Wi-Fi networks?",
                "options": [
                    "Loss of encryption",
                    "Lack of access control",
                    "Increased network performance",
                    "All of the above"
                ],
                "correctAnswer": 1,
                "category": "Wi-Fi Risks"
            },
            {
                "question": "What type of attack targets the availability of a wireless network by jamming signals?",
                "options": [
                    "DoS Attack",
                    "Evil Twin Attack",
                    "Rogue AP Attack",
                    "WEP Cracking"
                ],
                "correctAnswer": 0,
                "category": "Wireless Attacks"
            },
            {
                "question": "Which of the following technologies is used for secure communication on Wi-Fi networks?",
                "options": [
                    "SSL/TLS",
                    "WPA3",
                    "WEP",
                    "DNSSEC"
                ],
                "correctAnswer": 1,
                "category": "Wi-Fi Security Technologies"
            },
            {
                "question": "Which of the following actions helps mitigate the risk of Wi-Fi jamming?",
                "options": [
                    "Using stronger encryption",
                    "Changing the channel of the wireless router",
                    "Increasing the signal power",
                    "Using a VPN"
                ],
                "correctAnswer": 1,
                "category": "Wi-Fi Security"
            },
            {
                "question": "What is a potential consequence of a successful Evil Twin attack?",
                "options": [
                    "Network traffic interception",
                    "Network denial",
                    "Wi-Fi signal encryption",
                    "Device authentication"
                ],
                "correctAnswer": 0,
                "category": "Evil Twin Attacks"
            }
        ],
        icon: "fa-user-shield",
        color: "cybersecurity",
        difficulty: "Easy",
        participants: 6,
        description: "Test your knowledge of basic cybersecurity concepts."
    },
    "CEH Lesson 17": {
        questions: [
            {
                "question": "Which of the following is a common security vulnerability in mobile apps?",
                "options": [
                    "Insecure communication",
                    "Code tampering",
                    "Improper credential storage",
                    "All of the above"
                ],
                "correctAnswer": 3,
                "category": "Mobile App Vulnerabilities"
            },
            {
                "question": "Which of the following is a method for exploiting Android vulnerabilities?",
                "options": [
                    "Rooting the device",
                    "Jailbreaking the device",
                    "Using a weak PIN code",
                    "All of the above"
                ],
                "correctAnswer": 0,
                "category": "Android Vulnerabilities"
            },
            {
                "question": "Which of the following is a common attack method against iOS devices?",
                "options": [
                    "Rooting",
                    "Jailbreaking",
                    "Sideloading apps from untrusted sources",
                    "All of the above"
                ],
                "correctAnswer": 1,
                "category": "iOS Vulnerabilities"
            },
            {
                "question": "What is the main security risk associated with jailbreaking an iOS device?",
                "options": [
                    "It bypasses Apple's security restrictions",
                    "It makes the device immune to malware",
                    "It prevents unauthorized app installation",
                    "It enhances battery life"
                ],
                "correctAnswer": 0,
                "category": "Jailbreaking"
            },
            {
                "question": "Which of the following is an example of a Mobile Device Management (MDM) tool?",
                "options": [
                    "Microsoft Intune",
                    "Frida",
                    "MobSF",
                    "Cydia"
                ],
                "correctAnswer": 0,
                "category": "MDM Tools"
            },
            {
                "question": "What does Mobile Device Management (MDM) allow administrators to do?",
                "options": [
                    "Monitor network traffic",
                    "Enforce security policies on mobile devices",
                    "Hack devices remotely",
                    "Disable physical access to devices"
                ],
                "correctAnswer": 1,
                "category": "Mobile Device Management"
            },
            {
                "question": "Which of the following is a common mobile malware delivery method?",
                "options": [
                    "Malicious apps from unofficial app stores",
                    "SMS phishing",
                    "Bluetooth vulnerabilities",
                    "All of the above"
                ],
                "correctAnswer": 3,
                "category": "Mobile Malware"
            },
            {
                "question": "What is the purpose of enabling full-disk encryption on a mobile device?",
                "options": [
                    "To prevent unauthorized access to stored data",
                    "To improve device performance",
                    "To block incoming network traffic",
                    "To increase device battery life"
                ],
                "correctAnswer": 0,
                "category": "Mobile Security Best Practices"
            },
            {
                "question": "Which of the following is an example of an insecure mobile communication protocol?",
                "options": [
                    "HTTPS",
                    "WPA3",
                    "Bluetooth",
                    "HTTP"
                ],
                "correctAnswer": 3,
                "category": "Insecure Communication"
            },
            {
                "question": "Which of the following is the best way to prevent mobile malware infections?",
                "options": [
                    "Using official app stores for downloading apps",
                    "Disabling all mobile security features",
                    "Rooting the device",
                    "Downloading apps from unknown sources"
                ],
                "correctAnswer": 0,
                "category": "Mobile Security"
            },
            {
                "question": "Which of the following is a defense strategy against mobile app vulnerabilities?",
                "options": [
                    "Code signing and verification",
                    "Storing sensitive data in plaintext",
                    "Using weak passwords",
                    "Disabling all authentication measures"
                ],
                "correctAnswer": 0,
                "category": "Mobile App Security"
            },
            {
                "question": "What is a key security feature of the Secure Enclave in iOS devices?",
                "options": [
                    "It stores sensitive data such as encryption keys and biometric data securely",
                    "It controls the Wi-Fi signal",
                    "It prevents unauthorized app installation",
                    "It enhances battery life"
                ],
                "correctAnswer": 0,
                "category": "iOS Security"
            },
            {
                "question": "Which of the following is the best way to protect sensitive data stored on a mobile device?",
                "options": [
                    "Use full-disk encryption",
                    "Disable the screen lock",
                    "Store sensitive data in plain text",
                    "Avoid using security software"
                ],
                "correctAnswer": 0,
                "category": "Mobile Data Protection"
            }
        ],
        icon: "fa-user-shield",
        color: "cybersecurity",
        difficulty: "Easy",
        participants: 6,
        description: "Test your knowledge of basic cybersecurity concepts."
    },
    "CEH Lesson 18": {
        questions: [
            {
                "question": "Which of the following is a common security vulnerability in IoT devices?",
                "options": [
                    "Weak default credentials",
                    "Lack of encryption",
                    "Unpatched firmware",
                    "All of the above"
                ],
                "correctAnswer": 3,
                "category": "IoT Vulnerabilities"
            },
            {
                "question": "Which IoT protocol is commonly used for communication in IoT devices?",
                "options": [
                    "MQTT",
                    "HTTP",
                    "FTP",
                    "SMTP"
                ],
                "correctAnswer": 0,
                "category": "IoT Protocols"
            },
            {
                "question": "Which type of attack exploits weak default credentials in IoT devices to create a botnet?",
                "options": [
                    "DDoS Attack",
                    "Man-in-the-Middle",
                    "Rogue AP Attack",
                    "Botnet-based DDoS Attack"
                ],
                "correctAnswer": 3,
                "category": "IoT Attacks"
            },
            {
                "question": "Which of the following is a common IoT security best practice?",
                "options": [
                    "Changing default passwords",
                    "Leaving devices in open networks",
                    "Not applying firmware updates",
                    "Using unsecured communication protocols"
                ],
                "correctAnswer": 0,
                "category": "IoT Security Best Practices"
            },
            {
                "question": "Which of the following tools is used for reconnaissance on IoT devices?",
                "options": [
                    "Shodan",
                    "Wireshark",
                    "Metasploit",
                    "Aircrack-ng"
                ],
                "correctAnswer": 0,
                "category": "IoT Reconnaissance"
            },
            {
                "question": "Which attack method involves manipulating the communication between IoT devices?",
                "options": [
                    "Man-in-the-Middle Attack",
                    "Credential Stuffing",
                    "SQL Injection",
                    "Session Hijacking"
                ],
                "correctAnswer": 0,
                "category": "IoT Attacks"
            },
            {
                "question": "Which of the following is a method used for post-exploitation in IoT environments?",
                "options": [
                    "Firmware hijacking",
                    "Brute Force Attacks",
                    "Phishing",
                    "Port Scanning"
                ],
                "correctAnswer": 0,
                "category": "IoT Post-Exploitation"
            },
            {
                "question": "What is a key security concern when using IoT devices in critical infrastructure?",
                "options": [
                    "Lack of physical access control",
                    "Network exposure to attacks",
                    "Use of weak cryptography",
                    "All of the above"
                ],
                "correctAnswer": 3,
                "category": "IoT Security"
            },
            {
                "question": "What is the purpose of a mobile device management (MDM) solution in an IoT environment?",
                "options": [
                    "To enforce security policies on IoT devices",
                    "To hack into IoT devices",
                    "To monitor network traffic",
                    "To install malware on devices"
                ],
                "correctAnswer": 0,
                "category": "IoT Management"
            },
            {
                "question": "What is the main risk of unsecured IoT devices in industrial control systems (ICS)?",
                "options": [
                    "Data theft",
                    "Denial of service attacks",
                    "Tampering with control processes",
                    "All of the above"
                ],
                "correctAnswer": 3,
                "category": "IoT in OT"
            },
            {
                "question": "Which of the following protocols is commonly used for communication in OT systems like SCADA?",
                "options": [
                    "Modbus",
                    "MQTT",
                    "HTTP",
                    "FTP"
                ],
                "correctAnswer": 0,
                "category": "OT Protocols"
            },
            {
                "question": "What is the best practice for securing IoT devices in a corporate environment?",
                "options": [
                    "Isolate IoT devices on separate VLANs",
                    "Use default settings",
                    "Allow external access to IoT devices",
                    "Install malware scanners on IoT devices"
                ],
                "correctAnswer": 0,
                "category": "IoT Network Security"
            }
        ],
        icon: "fa-user-shield",
        color: "cybersecurity",
        difficulty: "Easy",
        participants: 6,
        description: "Test your knowledge of basic cybersecurity concepts."
    },
    "CEH Lesson 19": {
        questions: [
            {
                "question": "Which cloud service model provides virtualized hardware resources?",
                "options": [
                    "IaaS",
                    "PaaS",
                    "SaaS",
                    "DaaS"
                ],
                "correctAnswer": 0,
                "category": "Cloud Models"
            },
            {
                "question": "Which of the following is a security concern related to cloud environments?",
                "options": [
                    "Misconfigured storage buckets",
                    "Credential leaks",
                    "Insecure APIs",
                    "All of the above"
                ],
                "correctAnswer": 3,
                "category": "Cloud Security Concerns"
            },
            {
                "question": "What is the primary purpose of the shared responsibility model in cloud computing?",
                "options": [
                    "To allocate security responsibilities between the cloud provider and the customer",
                    "To protect customer data from cloud providers",
                    "To enforce encryption on all cloud services",
                    "To ensure compliance with all regulatory frameworks"
                ],
                "correctAnswer": 0,
                "category": "Cloud Security Models"
            },
            {
                "question": "Which of the following cloud services provides a platform for developing, running, and managing applications without dealing with infrastructure?",
                "options": [
                    "IaaS",
                    "PaaS",
                    "SaaS",
                    "FaaS"
                ],
                "correctAnswer": 1,
                "category": "Cloud Service Models"
            },
            {
                "question": "Which of the following is a common method used by attackers to exploit cloud vulnerabilities?",
                "options": [
                    "Exposing storage buckets",
                    "Credential stuffing",
                    "API key leaks",
                    "All of the above"
                ],
                "correctAnswer": 3,
                "category": "Cloud Exploits"
            },
            {
                "question": "Which of the following tools is used for penetration testing in cloud environments?",
                "options": [
                    "PACU",
                    "Metasploit",
                    "Nmap",
                    "Wireshark"
                ],
                "correctAnswer": 0,
                "category": "Cloud Penetration Testing"
            },
            {
                "question": "What is the purpose of Cloud Access Security Brokers (CASBs)?",
                "options": [
                    "To manage and enforce security policies for cloud services",
                    "To monitor network traffic",
                    "To provide DDoS protection",
                    "To create encrypted cloud storage"
                ],
                "correctAnswer": 0,
                "category": "Cloud Security Tools"
            },
            {
                "question": "Which of the following is a key security practice in cloud environments?",
                "options": [
                    "Data encryption",
                    "Patch management",
                    "Multi-factor authentication",
                    "All of the above"
                ],
                "correctAnswer": 3,
                "category": "Cloud Security Best Practices"
            },
            {
                "question": "Which cloud security service is used to monitor malicious activities in real-time?",
                "options": [
                    "AWS GuardDuty",
                    "Azure Security Center",
                    "Cloudflare",
                    "Google Cloud Security"
                ],
                "correctAnswer": 0,
                "category": "Cloud Security Monitoring"
            },
            {
                "question": "Which of the following is the most significant challenge when securing cloud environments?",
                "options": [
                    "Lack of visibility and control over data",
                    "Overuse of third-party tools",
                    "Storage cost management",
                    "Cloud provider security compliance"
                ],
                "correctAnswer": 0,
                "category": "Cloud Security Challenges"
            },
            {
                "question": "Which of the following can help secure cloud-based APIs?",
                "options": [
                    "Rate limiting",
                    "API key rotation",
                    "Access control lists",
                    "All of the above"
                ],
                "correctAnswer": 3,
                "category": "Cloud API Security"
            },
            {
                "question": "What is the primary advantage of containerization in cloud environments?",
                "options": [
                    "Faster application development and deployment",
                    "Reduced system vulnerabilities",
                    "Limited access control",
                    "Improved data privacy"
                ],
                "correctAnswer": 0,
                "category": "Cloud Container Security"
            }
        ],
        icon: "fa-user-shield",
        color: "cybersecurity",
        difficulty: "Easy",
        participants: 6,
        description: "Test your knowledge of basic cybersecurity concepts."
    },
    "CEH Lesson 20": {
        questions: [
            {
                "question": "What is the primary purpose of cryptography in cybersecurity?",
                "options": [
                    "To ensure confidentiality, integrity, and authentication",
                    "To monitor network traffic",
                    "To exploit vulnerabilities",
                    "To perform penetration testing"
                ],
                "correctAnswer": 0,
                "category": "Cryptography Basics"
            },
            {
                "question": "Which of the following is an example of symmetric encryption?",
                "options": [
                    "AES",
                    "RSA",
                    "ECC",
                    "DSA"
                ],
                "correctAnswer": 0,
                "category": "Symmetric Encryption"
            },
            {
                "question": "Which of the following algorithms is used for public key encryption?",
                "options": [
                    "AES",
                    "RSA",
                    "DES",
                    "Blowfish"
                ],
                "correctAnswer": 1,
                "category": "Asymmetric Encryption"
            },
            {
                "question": "What is a primary use case for hashing algorithms like SHA-256?",
                "options": [
                    "Encrypting data for secure transmission",
                    "Generating unique identifiers",
                    "Storing passwords securely",
                    "Decrypting encrypted data"
                ],
                "correctAnswer": 2,
                "category": "Cryptography Applications"
            },
            {
                "question": "Which cryptographic protocol is commonly used to secure communication over the internet?",
                "options": [
                    "TLS/SSL",
                    "IPsec",
                    "SSH",
                    "All of the above"
                ],
                "correctAnswer": 3,
                "category": "Secure Communication"
            },
            {
                "question": "Which of the following is a common cryptographic attack technique?",
                "options": [
                    "Brute-force attack",
                    "Side-channel attack",
                    "Rainbow table attack",
                    "All of the above"
                ],
                "correctAnswer": 3,
                "category": "Cryptanalysis"
            },
            {
                "question": "Which of the following is the most widely used cryptographic hash function?",
                "options": [
                    "MD5",
                    "SHA-1",
                    "SHA-256",
                    "AES"
                ],
                "correctAnswer": 2,
                "category": "Cryptography Algorithms"
            },
            {
                "question": "Which of the following is a primary characteristic of asymmetric encryption?",
                "options": [
                    "Same key is used for encryption and decryption",
                    "Two different keys are used for encryption and decryption",
                    "Faster than symmetric encryption",
                    "Not widely used"
                ],
                "correctAnswer": 1,
                "category": "Asymmetric Encryption"
            },
            {
                "question": "Which cryptographic algorithm is commonly used for digital signatures?",
                "options": [
                    "RSA",
                    "AES",
                    "SHA",
                    "Blowfish"
                ],
                "correctAnswer": 0,
                "category": "Cryptography Applications"
            },
            {
                "question": "What is the key challenge with RSA encryption in a post-quantum world?",
                "options": [
                    "It can be broken by quantum computers",
                    "It uses too much bandwidth",
                    "It is too slow for real-time communication",
                    "It relies on symmetric encryption"
                ],
                "correctAnswer": 0,
                "category": "Post-Quantum Cryptography"
            },
            {
                "question": "Which of the following is an example of a public key infrastructure (PKI) component?",
                "options": [
                    "Certificate Authority (CA)",
                    "Encryption Key",
                    "TLS Protocol",
                    "AES Key"
                ],
                "correctAnswer": 0,
                "category": "Public Key Infrastructure"
            },
            {
                "question": "What is the purpose of Diffie-Hellman in cryptography?",
                "options": [
                    "To generate a shared secret key over an insecure channel",
                    "To encrypt data using a public key",
                    "To hash sensitive data",
                    "To verify a digital signature"
                ],
                "correctAnswer": 0,
                "category": "Key Exchange"
            },
            {
                "question": "What is the main reason for using encryption in data security?",
                "options": [
                    "To increase performance",
                    "To ensure data integrity",
                    "To protect sensitive data from unauthorized access",
                    "To authenticate users"
                ],
                "correctAnswer": 2,
                "category": "Encryption"
            }
        ],
        icon: "fa-user-shield",
        color: "cybersecurity",
        difficulty: "Easy",
        participants: 6,
        description: "Test your knowledge of basic cybersecurity concepts."
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