- GitHub Repository: https://github.com/Tessy-123/SecureAudit-Windows-VM
- Deployed Portfolio: https://Tessy-123.github.io/SecureAudit-Windows-VM/

# SecureAudit — Windows System Security Assessment

SecureAudit is an interactive defensive security auditing web application designed for ethical assessment of an authorised Windows virtual machine. It guides an assessor through four security areas, records control findings, calculates an overall security score, and generates downloadable audit reports.

> [!IMPORTANT]
> This project is a browser-based assessment and training tool. It uses simulated diagnostic output and does not execute PowerShell commands or make changes to the user's Windows system.

## Live Application

- **GitHub Repository:** https://github.com/Tessy-123/SecureAudit-Windows-VM
- **Deployed Portfolio:** https://Tessy-123.github.io/SecureAudit-Windows-VM/

## Features

- VM scope and assessor details
- Ethical authorisation confirmation before assessment
- Four assessment areas:
  - Account Privileges
  - Security Policies
  - Firewall Settings
  - System Configuration
- Sixteen configurable security controls
- PASS, WARN, and FAIL status classifications
- Simulated PowerShell diagnostic output
- Domain and overall security score calculations
- Weaknesses and remediation recommendations
- Unhardened baseline demo mode
- Print or save the report as PDF
- Download the report as TXT or HTML

## Assessment Areas

| Assessment Area | Included Controls |
|---|---|
| Account Privileges | Administrator account status, Administrators membership, Guest account, and password expiration |
| Security Policies | Password complexity, minimum password length, account lockout, and audit logging |
| Firewall Settings | Domain and Private profiles, Public profile, inbound policy, and inbound rules |
| System Configuration | Windows updates, antivirus protection, UAC, and legacy service hardening |

## Technology

- HTML5
- CSS3
- Vanilla JavaScript
- GitHub Pages

No frameworks, APIs, external packages, or backend services are required.

## Project Structure

```text
.
├── index.html    # Application structure and pages
├── style.css     # Dark navy theme and responsive layouts
├── app.js        # Assessment data, scoring, navigation, and reports
└── README.md     # Project documentation
```

## Run Locally

1. Clone the repository:

   ```powershell
   git clone https://github.com/Tessy-123/SecureAudit-Windows-VM.git
   ```

2. Enter the project directory:

   ```powershell
   cd SecureAudit-Windows-VM
   ```

3. Open `index.html` directly in a browser, or start a local server:

   ```powershell
   python -m http.server 8000
   ```

4. Visit `http://localhost:8000`.

## How to Use

1. Enter the authorised VM hostname, operating system, virtualisation platform, and auditor name.
2. Confirm that the assessment is being performed on an explicitly authorised VM.
3. Open each assessment area from the assessment hub.
4. Select the observed state for every control.
5. Review the calculated domain and overall scores.
6. Open the final report to review weaknesses and remediation commands.
7. Print or download the completed report.

## Security and Ethical Use

SecureAudit is intended only for authorised security awareness, education, and defensive auditing activities. Do not use its assessment results or remediation commands against systems for which you do not have explicit permission.

The displayed PowerShell commands are reference and remediation examples. Review them and apply them only in an approved and controlled environment.

## Author

**Chinsinsi Msanyama**

## License

Add a license if the project will be distributed or reused publicly.
