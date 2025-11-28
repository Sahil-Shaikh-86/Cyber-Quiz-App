const questions = {
  networking:
  [
    // Easy 
    { question:"A firewall is used to:", 
      options:["Encrypt files","Prevent unauthorized access","Increase internet speed","Store passwords"],
      answer:1, 
      level:"easy" 
    },
    { question:"VPN stands for:",
      options:["Verified Private Network","Virtual Proxy Node","Verified Public Network","Virtual Private Network"],
      answer:3, 
      level:"easy" 
    },
    { question:"HTTPS protocol ensures:", 
      options:["Data confidentiality","Faster download","Virus removal","Cloud backup"], 
      answer:0, 
      level:"easy"
    },
    { question:"Which device connects multiple networks together?", 
      options:["Hub","Switch","Router","Modem"], 
      answer:2, 
      level:"easy" 
    },
    { question:"WPA2 is used to secure:", 
      options:["Websites","Wireless networks","Emails","Cloud storage"], 
      answer:1, 
      level:"easy" 
    },
    { question:"Antivirus software primarily protects against:", 
      options:["Spam emails","Weak passwords","Internet speed issues","Malware"], 
      answer:3, 
      level:"easy"
    },
    { question:"Which one is a strong password?", 
      options:["123456","qwerty","Kr!shna#2025","password"], 
      answer:2, 
      level:"easy" 
    },
    { question:"Which protocol is used for email sending?", 
      options:["SMTP","FTP","HTTP","SSH"], 
      answer:0, 
      level:"easy" 
    },
    { question:"What does IP stand for?",
      options:["Intellectual Property","Internal Password","Internet Protocol","Input Packet"], 
      answer:2, 
      level:"easy" 
    },
    { question:"A switch is mainly used to:", 
      options:["Connect multiple devices within a network","Filter malware","Encrypt data","Monitor traffic"],
      answer:0, 
      level:"easy" 
    },
    { question:"A router's main function is to:", 
      options:["Encrypt files","Detect malware","Block spam","Connect networks"], 
      answer:3, 
      level:"easy" 
    },
    { question:"Which device operates at the physical layer only?", 
      options:["Router","Hub","Switch","Firewall"], 
      answer:1, 
      level:"easy" 
    },
    { question:"WPA stands for:", 
      options:["Wireless Privacy Algorithm","Web Protected Application","Wireless Protected Access","Web Privacy Access"], 
      answer:2, 
      level:"easy" 
    },
    { question:"Which port does HTTP use by default?", 
      options:["443","80","69","21"], 
      answer:1, 
      level:"easy" 
    },
    { question:"Data encryption ensures:", 
      options:["Data integrity","Faster transfer","Availability","Confidentiality"], 
      answer:3, 
      level:"easy" 
    },

    // Medium 
    { question:"IDS stands for:", 
        options:["Internet Defense System","Integrated Device Service","Internal Data Security","Intrusion Detection System"], 
        answer:3, 
        level:"medium" 
    },
    { question:"Which attack floods a network with traffic?", 
        options:["Phishing","DoS attack","Man-in-the-middle","SQL Injection"], 
        answer:1, 
        level:"medium" 
    },
    { question:"SSL certificates are used to:", 
        options:["Encrypt emails","Block malware","Authenticate websites","Filter spam"], 
        answer:2, 
        level:"medium" 
    },
    { question:"What is a honeypot?", 
        options:["Trap for attackers","Malware removal tool","Backup system","Encryption protocol"], 
        answer:0,
        level:"medium" 
    },
    { question:"Brute force attacks target:", 
        options:["Firewall rules","Antivirus software","Email servers","Passwords"], 
        answer:3, 
        level:"medium" 
    },
    { question:"DMZ stands for:", 
        options:["Demilitarized Zone","Data Management Zone","Direct Memory Zone","Domain Management Zone"], 
        answer:0, 
        level:"medium" 
    },
    { question:"Which Wi-Fi standard is most secure?", 
        options:["WEP","WPA","WPA2","WPA3"], 
        answer:3, 
        level:"medium" 
    },
    { question:"Packet sniffers are used to:", 
        options:["Encrypt data","Monitor network traffic","Block viruses","Detect phishing"], 
        answer:1, 
        level:"medium" 
    },
    { question:"Man-in-the-middle attacks occur at:", 
        options:["Physical layer","Network layer","Communication channel","Application layer"], 
        answer:2, 
        level:"medium" 
    },
    { question:"Which protocol allows secure remote login?", 
        options:["SSH","Telnet","FTP","HTTP"], 
        answer:0, 
        level:"medium" 
    },
    { question:"VPN provides:", 
        options:["Faster internet","Secured and private network","Spam filtering","Malware protection"], 
        answer:1, 
        level:"medium" 
    },
    { question:"Which device filters traffic based on rules?", 
        options:["Switch","Hub","Firewall","Router"], 
        answer:2, 
        level:"medium" 
    },
    { question:"Which encryption type is symmetric?", 
        options:["AES","RSA","ECC","Diffie-Hellman"], 
        answer:0, 
        level:"medium" 
    },
    { question:"WPA3 improves security by:", 
        options:["Shorter keys","Reducing bandwidth","Slower communication","Longer keys"], 
        answer:3, 
        level:"medium" 
    },
    { question:"Intrusion Prevention System (IPS) differs from IDS that it:", 
        options:["Only monitors","Prevents attacks","Encrypts packets","Increases speed"], 
        answer:1, 
        level:"medium" 
    },

    // Hard (15)
    { question:"Which IP address is private?", 
        options:["8.8.8.8","123.45.67.89","192.168.1.1","172.32.0.1"], 
        answer:2, 
        level:"hard" 
    },
    { question:"Which is a network authentication protocol?", 
        options:["Kerberos","SHA-256","AES","SSL"], 
        answer:0, 
        level:"hard" 
    },
    { question:"ARP spoofing attacks target:", 
        options:["Web browsers","DNS servers","Firewalls","MAC address table"], 
        answer:3, 
        level:"hard" 
    },
    { question:"Which port does HTTPS use by default?", 
        options:["22","80","443","69"], 
        answer:2, 
        level:"hard" 
    },
    { question:"Honeypots are mainly deployed to:", 
        options:["Improve speed","Detect attackers","Encrypt data","Filter spam"], 
        answer:1, 
        level:"hard" 
    },
    { question:"SSL/TLS works at which layer of OSI?", 
        options:["Physical","Data link","Network","Transport"], 
        answer:3, 
        level:"hard" 
    },
    { question:"VPN tunneling uses:", 
        options:["Plain packets","Encrypted packets","Broadcast packets","Multicast only"], 
        answer:1, 
        level:"hard" 
    },
    { question:"Which attack exploits software vulnerabilities before patches are released?", 
        options:["Phishing","DoS","Zero-day attack","Man-in-the-middle"], 
        answer:2, 
        level:"hard" 
    },
    { question:"MAC address filtering is implemented at:", 
        options:["Network layer","Application layer","Transport layer","Data link layer"], 
        answer:3, 
        level:"hard" 
    },
    { question:"Network segmentation helps to:", 
        options:["Increase latency","Reduce attack surface","Block emails","Encrypt files"], 
        answer:1, 
        level:"hard" 
    },
    { question:"WPA2 uses which encryption algorithm?", 
        options:["AES","DES","RSA","MD5"], 
        answer:0, 
        level:"hard" 
    },
    { question:"Which technique is used to prevent ARP spoofing?", 
        options:["VPN","DNS filtering","MAC filtering","SSL"], 
        answer:2, 
        level:"hard" 
    },
    { question:"Intrusion Detection System (IDS) is:", 
        options:["Preventive","Firewall","Encryption tool","Detective"], 
        answer:3, 
        level:"hard" 
    },
    { question:"IPsec provides:", 
        options:["Network-level encryption","Application-level firewall","Antivirus protection","Password recovery"],
        answer:0, 
        level:"hard" 
    },
    { question:"Which attack can bypass firewall rules?", 
        options:["Port scanning","Phishing","VPN tunneling","Brute force"], 
        answer:2, 
        level:"hard" 
    }
  ],

  cyberlaws:
  [
    { question:"Cyber laws mainly aim to:", 
        options:["Improve internet speed","promote social media","Regulate digital crimes","Build websites"], 
        answer:2, 
        level:"easy" 
    },
    { question:"Phishing is:", 
        options:["A social engineering attack","Spyware","Malware","Firewall protocol"], 
        answer:0, 
        level:"easy" 
    },
    { question:"CERT-In in India handles:", 
        options:["Speed optimization","Cloud storage","Website development","Cybersecurity incidents"], 
        answer:3, 
        level:"easy" 
    },
    { question:"GDPR applies to which region?", 
        options:["USA","India","EU","Japan"], 
        answer:2, 
        level:"easy" 
    },
    { question:"Identity theft online is considered:", 
        options:["Legal","Cybercrime","Safe practice","Ethical"], 
        answer:1, 
        level:"easy" 
    },
    { question:"Intellectual property violation example:", 
        options:["Copying licensed software without permission","Using songs by giving credit","Strong password use","Cloud storage"], 
        answer:0, 
        level:"easy"
    },
    { question:"Cyber bullying refers to:", 
        options:["Hacking networks","Online Gambling","Online harassment","Encrypting files"], 
        answer:2, 
        level:"easy"
    },
    { question:"Which law regulates E-commerce in India?", 
        options:["IT Act 2000","IPC 1860","Companies Act","Cybersecurity Act"], 
        answer:0, 
        level:"easy" 
    },
    { question:"Cybercrime includes:", 
        options:["Emailing friends","Watching Movies","E-sports Gaming","Hacking"], 
        answer:3, 
        level:"easy" 
    },
    { question:"Section 66 of IT Act covers:", 
        options:["Crime","Hacking","Privacy violation","Cyber terrorism"], 
        answer:1, 
        level:"easy" 
    },
    { question:"Publishing obscene content online is punishable under:", 
        options:["Section 65","Section 66","Section 67","Section 70"], 
        answer:2, 
        level:"easy" 
    },
    { question:"Digital signatures are used for:", 
        options:["Authenticating digital documents","Encrypting websites","Malware Detection","Password recovery"], 
        answer:0, 
        level:"easy" 
    },
    { question:"Cyber law protects:", 
        options:["Websites only","Hardware & Software","Emails","Software, data, and digital communications"], 
        answer:3, 
        level:"easy" 
    },
    { question:"Identity theft can involve:", 
        options:["Using VPN","Strong passwords","Using someones personal info illegally","Email encryption"], 
        answer:2, 
        level:"easy" 
    },
    { question:"Online fraud can include:", 
        options:["Software update","Fake job offers","Browsing websites","Online Gaming"], 
        answer:1, 
        level:"easy" 
    },

    // Medium 
    { question:"Section 43A of IT Act deals with:", 
        options:["Hacking","Obscene content","Privacy protection","Cyber terrorism"], 
        answer:2, 
        level:"medium" 
    },
    { question:"Cyber defamation involves:", 
        options:["Sending malware","Spamming emails","Hacking a network","Damaging someones reputation online"], 
        answer:3, 
        level:"medium" 
    },
    { question:"Section 66C deals with:", 
        options:["Identity theft","Publishing obscene content","Cyber terrorism","Privacy"], 
        answer:0, 
        level:"medium" 
    },
    { question:"Cyber espionage refers to:", 
        options:["Using VPN","Emailing","Spying for sensitive information","Encrypting files"], 
        answer:2, 
        level:"medium" 
    },
    { question:"Intellectual property includes:", 
        options:["Only patents","Patents, copyright, trademarks","Only software","Only hardware"], 
        answer:1, 
        level:"medium" 
    },
    { question:"Cyber terrorism is punishable under:", 
        options:["Section 66F","Section 66C","Section 72","Section 80"], 
        answer:0, 
        level:"medium" 
    },
    { question:"Online stalking is a:", 
        options:["Safe browsing","Legal activity","Cybercrime","Network attack"], 
        answer:2, 
        level:"medium" 
    },
    { question:"Cybercrime can involve:", 
        options:["Updating software","Browsing social media","Using email","Hacking, phishing, and malware attacks"], 
        answer:3, 
        level:"medium" 
    },
    { question:"Digital signature uses:", 
       options:["Password recovery","Encryption","Antivirus","VPN"], 
       answer:1, 
       level:"medium" 
    },
    { question:"Section 72 of IT Act covers:", 
        options:["Hacking","Obscene content","Privacy breach","Cyber terrorism"], 
        answer:2, 
        level:"medium" 
    },
    { question:"Cyber fraud includes:", 
        options:["Sending fake invoices online","Using firewall","Updating software","Encrypting files"], 
        answer:0, 
        level:"medium" 
    },
    { question:"CERT-In stands for:", 
        options:["Cyber Ethics Research Team","Cyber Emergency Regulation Team","Computer Education & Response Team","Computer Emergency Response Team"], 
        answer:3, 
        level:"medium" 
    },
    { question:"Online harassment is also called as:", 
        options:["Cyber bullying","Cyber espionage","Malware attack","Phishing"], 
        answer:0, 
        level:"medium" 
    },
    { question:"Copyright protection applies to:", 
        options:["Email addresses","Software code","Bank passwords","Firewalls"], 
        answer:1, 
        level:"medium" 
    },
    { question:"Cyber law punishments may include:", 
        options:["Website blocking","Only warnings","Fine","Fines and imprisonment"], 
        answer:3, 
        level:"medium" 
    },

    // Hard 
    { question:"Section 66E of IT Act covers:", 
        options:["Hacking","Privacy violation","Identity theft","Cyber terrorism"], 
        answer:1, 
        level:"hard" 
    },
    { question:"Zero-day cybercrime refers to:", 
        options:["Exploit before patch is released","Spam email","Fake websites","Identity theft"],
        answer:0, 
        level:"hard" 
    },
    { question:"Digital signature certificate is issued by:", 
        options:["ISP","Any private company","Email service provider","Government-approved certifying authority"], 
        answer:3, 
        level:"hard" 
    },
    { question:"Section 66F includes:", 
        options:["Email spam","Cyber terrorism","Cyber defamation","Identity theft"], 
        answer:1, 
        level:"hard" 
    },
    { question:"IT Act amendment of 2008 strengthened:", 
        options:["Cyber terrorism and privacy laws","Hardware security","Internet speed","Browser protection"], 
        answer:0, 
        level:"hard" 
    },
    { question:"Cyber crime reporting can be done to:", 
        options:["Browser developer","ISP only","Local police & CERT-In","VPN provider"], 
        answer:2, 
        level:"hard" 
    },
    { question:"Phishing attacks can target:",
         options:["Network cables","Email encryption","Firewalls","Bank credentials"], 
         answer:3, 
         level:"hard" 
    },
    { question:"Cyber law helps protect:", 
        options:["Intellectual property","Only hardware","Email spam","Cloud storage speed"], 
        answer:0, 
        level:"hard" 
    },
    { question:"Section 69A allows:", 
        options:["Banks to encrypt","Users to delete data","Government to block websites","VPN creation"], 
        answer:2, 
        level:"hard" 
    },
    { question:"Cyber terrorism is:", 
        options:["Attacks on computers or networks to harm citizens","Email spam","Downloading games","VPN tunneling"], 
        answer:0, 
        level:"hard" 
    },
    { question:"Section 66B of IT Act covers:", 
        options:["Cyber terrorism","Obscene material","Privacy","Credit card fraud"], 
        answer:3, 
        level:"hard" 
    },
    { question:"Social engineering attacks are addressed in:", 
        options:["Companies Act","IT Act","Copyright Act","IPC"], 
        answer:1, 
        level:"hard" 
    },
    { question:"Section 72A protects:", 
        options:["Email spam","Firewall rules","VPN servers","Sensitive personal data"], 
        answer:3, 
        level:"hard" 
    },
    { question:"Cyber law also regulates:", 
        options:["Digital contracts and e-commerce","Internet speed","Hardware connections","Antivirus updates"], 
        answer:0, 
        level:"hard" 
    },
    { question:"Which of these is an example of cyber crime?", 
        options:["Emailing friends","Using antivirus","Hacking a bank account","Browsing websites"], 
        answer:2, 
        level:"hard" 
    }
  ],


  general:
  [
    { question:"Which is a Strong password example:",
      options:["123456","pass@123","QWERTY","Kr!shna#2025"],
      answer:3,
      level:"easy"
    },
    { question:"Antivirus software is used to:",
      options:["Detect & Remove Malware","Speed up system","Encrypt Data","Block Network Traffic"],
      answer:0,
      level:"easy"
    },
    { question:"Social Engineering attacks target:",
      options:["Human Brain","Hardware","Software","Firewalls"],
      answer:0,
      level:"easy"
    },
    { question:"Two factor authentication adds:",
      options:["Speed","Cost","Bandwidth","Extra Security"],
      answer:3,
      level:"easy"
    },
    { question:"Cyber Hygiene means:",
      options:["Safe Online Practices","Cleaning Hardware","Using VPN","Installing Apps"],
      answer:0,
      level:"easy"
    },
    { question:"Phishing emails aim to:",
      options:["Steal sensitive data","Encrypt data","Backup files","Filter spam"],
      answer:0,
      level:"easy"
    },
    { question:"Ransomware attacks:",
      options:["Block spam","Encrypt files and demand payment","Improve speed","Backup emails"],
      answer:1,
      level:"easy"
    },
    { question:"Zero-day attck refers to:",
      options:["Attack that lasts one day","Attack on zero servers","Attack with no code","Exploit before patch is available"],
      answer:3,
      level:"easy"
    },
    { question:"A botnet is:",
      options:["Group of infected computers","Antivirus tool","Secure VPN","Firewall protocol"],
      answer:0,
      level:"easy"
    },
    { question:"Cookies in a browser are used for:",
      options:["Malware removal","Blocking ads","Store user information","Encrypt passwords"],
      answer:2,
      level:"easy"
    },
    { question:"Trojan horse is:",
      options:["Firewall","Antivirus update","Malware disguised as Legitimate Software","Antivirus update"],
      answer:2,
      level:"easy"
    },
    { question:"Main goal of Cyber Security is :",
      options:["Privacy, Speed, Security","Confidentiality, Integrity, Availability","Encryption, Decryption, Storage","Speed, Accuracy, Reliability"],
      answer:1,
      level:"easy"
    },
    { question:"MFA Stands for:",
      options:["Multi-file Access","Multi-Firewall App","Multi-Folder Authorization ","Multi-Factor Authentication"],
      answer:3,
      level:"easy"
    },
    { question:"Biggest weakness in cybersecurity is often:",
      options:["Hardware","Human Error","Software","VPN"],
      answer:1,
      level:"easy"
    },
    { question:"Risky file extension examples:",
      options:[".txt","jpg",".exe","docx"],
      answer:2,
      level:"easy"
    },

    { question:"Firewall primary work is:",
      options:["Block unauthorized traffic","Encrypts data","Removes viruses","Monitor Social Media"],
      answer:0,
      level:"medium"
    },
    { question:"Which is a phishing example?",
      options:["Anti-virus alert","VPN login","Fake Bank email","System updates"],
      answer:2,
      level:"medium"
    },
    { question:"Social Engineering attack technique is:",
      options:["Firewall rule","Pretexting","Antivirus scan","Encryption"],
      answer:1,
      level:"medium"
    },
    { question:"Ransomware differs from virus because:",
      options:["It speed up the system","It deletes cookies","It encrypts E-mails","It demands payment"],
      answer:3,
      level:"medium"
    },
    { question:"VPN provides:",
      options:["Faster browsing","Anti-spam","Private & Secure connection","Password recovery"],
      answer:2,
      level:"medium"
    },
    { question:"A Honeypot is used to:",
      options:["Encrypt files","Attract Honey-bees","Filter ads","Trap hackers"],
      answer:3,
      level:"medium"
    },
    { question:"Brute force attacks target:",
      options:["Passwords","Firewall","Browser","VPN"],
      answer:0,
      level:"medium"
    },
    { question:"HTTP vs HTTPS:",
      options:["HTTP is secure","HTTPS is faster","HTTPS is secure","Both are same"],
      answer:2,
      level:"medium"
    },
    { question:"How Keylogger works?",
      options:["Deletes emails","Block Firewalls","Encrypt data","Record keystrokes"],
      answer:3,
      level:"medium"
    },
    { question:"Strong Password must include:",
      options:["Only Letters","Letters & Numbers","Letters, Numbers, Symbols","Numbers & Symbols"],
      answer:2,
      level:"medium"
    },
    { question:"MFA includes:",
      options:["Password & OTP","Something you know, have or are","Something you have","OTP only"],
      answer:1,
      level:"medium"
    },
    { question:"Botnets are used for:",
      options:["DDoS Attacks","Email Encryption","Password recovery","Filter spam"],
      answer:0,
      level:"medium"
    },
    { question:"Patch management provides:",
      options:["Hardware Failure","Social Engineering","Exploiting Vulneribilties","Nothing"],
      answer:2,
      level:"medium"
    },
    { question:"What Spyware do?:",
      options:["Encrypts files","Monitors user activity","Deletes Passwords","Block Antivirus"],
      answer:3,
      level:"medium"
    },
    { question:"IP spoofing is used to:",
      options:["Show user IP","Block cookies","Hide attacker IP","Update software"],
      answer:2,
      level:"medium"
    },

    { question:"SQL injection attcks target:",
      options:["Databases","Passwords","Multi-media files","VPN"],
      answer:0,
      level:"hard"
    },
    { question:"Cross-site scripting (XSS) affects:",
      options:["Emails","Antivirus","System Software","Websites"],
      answer:3,
      level:"hard"
    },
    { question:"Social engineering human attacks include:",
      options:["Malware installation","Phishing, Pretexting, Baiting","Modify Firewall","Phishing"],
      answer:1,
      level:"hard"
    },
    { question:"Advanced Persistent Threat (APT) means:",
      options:["Quick virus infection","Malware scan","Long-term targetted attack","Spamming attck"],
      answer:2,
      level:"hard"
    },
    { question:"Rootkit malware aims to:",
      options:["Hide malicious activity","Root the system","Encrypt files","Delete E-mails"],
      answer:0,
      level:"hard"
    },
    { question:"DNS spoofing attck targets:",
      options:["Domains","Email servers","Domain name resolution","VPN"],
      answer:2,
      level:"hard"
    },
    { question:"Phishing attacks can be prevented by:",
      options:["Fast Internet","Anti-virus software","Anti-malware software","Awareness Training"],
      answer:3,
      level:"hard"
    },
    { question:"Multi Layer security is also called as:",
      options:["Two factor authentication","Defense in depth","VPN + Firewall","IDS-IPS"],
      answer:1,
      level:"hard"
    },
    { question:"Password cracking can be done by:",
      options:["Spyware","Social media tools","Brute-force attacks","Email Phishing"],
      answer:2,
      level:"hard"
    },
    { question:"TLS encryption is used for:",
      options:["Secure web communication","Faster downloads","Malware Detection","Transporting certificates"],
      answer:0,
      level:"hard"
    },
    { question:"Cyber threat intelligence involves:",
      options:["Encrypting data only","Updating Passwords","Gathering information about attacks","Intilligent Attck methods"],
      answer:2,
      level:"hard"
    },
    { question:"Insider threats come from:",
      options:["System inside failures","Hackers Outside","Untrusted sources","Employees or trusted individuals"],
      answer:3,
      level:"hard"
    },
    { question:"An attacker injects malicious code into a machine learning training dataset, causing the deployed AI system to misclassify certain inputs while still passing accuracy checks. This is an example of:",
      options:["Model inversion attack","Data poisoning attack","Evasion attack","Adversarial reprogramming"],
      answer:1,
      level:"hard"
    },
    { question:"Which attack technique tries all possible keys but optimizes the process using time–memory trade-offs, often with precomputed tables?:",
      options:["Dictionary attack","Brute-force attack","Rainbow table Attack","Hybrid attack"],
      answer:2,
      level:"hard"
    },
    { question:"Which of the following best describes a logic bomb?:",
      options:["Malware hidden inside firmware to bypass detection","Malicious code triggered by a specific event or condition","Attack exploiting logical flaws in authentication protocols","A backdoor installed within software logic"],
      answer:1,
      level:"hard"
    },
  ]
};
