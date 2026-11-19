const ASSESSMENT_DOMAINS = [
  {
    id: "privileges",
    number: "01",
    title: "Account Privileges",
    summary: "User accounts, administrator access and password policies.",
    probeCmd: "Get-LocalUser | Select Name,Enabled,PasswordRequired; Get-LocalGroupMember -Group 'Administrators'",
    probeOutput: [
      "Local Users:",
      "  Administrator : Enabled=False | PasswordRequired=True",
      "  Guest         : Enabled=False | PasswordRequired=True",
      "  lab-admin     : Enabled=True  | PasswordRequired=True",
      "  student-user  : Enabled=True  | PasswordRequired=True",
      "Administrators Group: lab-admin, Domain/LAB-ADMIN"
    ],
    controls: [
      {
        id: "priv-1",
        name: "Built-in Administrator Account Status",
        desc: "Ensure the built-in Administrator account is disabled or renamed/hardened.",
        options: [
          { label: "Disabled (Recommended)", status: "PASS" },
          { label: "Enabled with strong password", status: "WARN" },
          { label: "Enabled with weak/blank password", status: "FAIL" }
        ],
        selected: 0,
        status: "PASS",
        remediation: "Disable-LocalUser -Name 'Administrator' to reduce attack surface.",
        fixCmd: "Disable-LocalUser -Name 'Administrator'"
      },
      {
        id: "priv-2",
        name: "Local Administrators Group Membership",
        desc: "Restrict local administrative privileges strictly to authorised personnel.",
        options: [
          { label: "Only authorised admin account(s)", status: "PASS" },
          { label: "Includes shared/service accounts", status: "WARN" },
          { label: "Standard/untrusted users included", status: "FAIL" }
        ],
        selected: 0,
        status: "PASS",
        remediation: "Remove unauthorised accounts from the local Administrators group.",
        fixCmd: "Remove-LocalGroupMember -Group 'Administrators' -Member 'untrusted-user'"
      },
      {
        id: "priv-3",
        name: "Guest Account Disabled",
        desc: "Verify the built-in Guest account remains disabled.",
        options: [
          { label: "Disabled", status: "PASS" },
          { label: "Enabled", status: "FAIL" }
        ],
        selected: 0,
        status: "PASS",
        remediation: "Keep the Guest account disabled on all Windows VM instances.",
        fixCmd: "Disable-LocalUser -Name 'Guest'"
      },
      {
        id: "priv-4",
        name: "Password Expiration & Policy Enforcement",
        desc: "Ensure user accounts enforce password expiration and do not use non-expiring passwords.",
        options: [
          { label: "Enforced across accounts", status: "PASS" },
          { label: "Some accounts set to Never Expire", status: "WARN" },
          { label: "Password expiration disabled", status: "FAIL" }
        ],
        selected: 0,
        status: "PASS",
        remediation: "Set maximum password age and review accounts with PasswordNeverExpires enabled.",
        fixCmd: "net accounts /maxpwage:60"
      }
    ]
  },
  {
    id: "policies",
    number: "02",
    title: "Security Policies",
    summary: "Password complexity, account lockout and Windows security settings.",
    probeCmd: "secedit /export /cfg C:\\Temp\\secpol.cfg; Get-Content C:\\Temp\\secpol.cfg | Select-String 'Password|Lockout'",
    probeOutput: [
      "PasswordComplexity = 1 (Enabled)",
      "MinimumPasswordLength = 12",
      "LockoutBadCount = 5",
      "ResetLockoutCount = 15",
      "LockoutDuration = 15"
    ],
    controls: [
      {
        id: "pol-1",
        name: "Password Complexity Requirement",
        desc: "Require passwords to meet complexity rules (uppercase, lowercase, digits/symbols).",
        options: [
          { label: "Enabled", status: "PASS" },
          { label: "Disabled", status: "FAIL" }
        ],
        selected: 0,
        status: "PASS",
        remediation: "Enable password complexity in Local Security Policy (PasswordComplexity = 1).",
        fixCmd: "secedit /configure /db secedit.sdb /cfg C:\\Windows\\security\\templates\\defltbase.inf"
      },
      {
        id: "pol-2",
        name: "Minimum Password Length",
        desc: "Enforce at least 12 characters for VM accounts.",
        options: [
          { label: "12+ characters", status: "PASS" },
          { label: "8 to 11 characters", status: "WARN" },
          { label: "Under 8 characters or none", status: "FAIL" }
        ],
        selected: 0,
        status: "PASS",
        remediation: "Configure minimum password length to at least 12 characters.",
        fixCmd: "net accounts /minpwlen:12"
      },
      {
        id: "pol-3",
        name: "Account Lockout Threshold",
        desc: "Lock accounts after repeated failed sign-in attempts to deter brute-force attacks.",
        options: [
          { label: "Locked after 3–5 invalid attempts", status: "PASS" },
          { label: "Locked after 6–10 attempts", status: "WARN" },
          { label: "No lockout threshold configured", status: "FAIL" }
        ],
        selected: 0,
        status: "PASS",
        remediation: "Set account lockout threshold to 5 invalid logon attempts.",
        fixCmd: "net accounts /lockoutthreshold:5"
      },
      {
        id: "pol-4",
        name: "Audit Policy & Security Event Logging",
        desc: "Ensure logon, privilege use, and policy change events are logged.",
        options: [
          { label: "Success & Failure audited", status: "PASS" },
          { label: "Partial audit logging enabled", status: "WARN" },
          { label: "Audit logging disabled", status: "FAIL" }
        ],
        selected: 0,
        status: "PASS",
        remediation: "Enable auditing for Logon/Logoff and Account Management events.",
        fixCmd: "auditpol /set /category:'Logon/Logoff' /success:enable /failure:enable"
      }
    ]
  },
  {
    id: "firewall",
    number: "03",
    title: "Firewall Settings",
    summary: "Firewall status, network profiles and inbound connections.",
    probeCmd: "Get-NetFirewallProfile | Select Name,Enabled,DefaultInboundAction,DefaultOutboundAction",
    probeOutput: [
      "Name            : Domain",
      "Enabled         : True",
      "DefaultInbound  : Block",
      "Name            : Private",
      "Enabled         : True",
      "DefaultInbound  : Block",
      "Name            : Public",
      "Enabled         : True",
      "DefaultInbound  : Block"
    ],
    controls: [
      {
        id: "fw-1",
        name: "Domain & Private Firewall Profiles",
        desc: "Confirm Windows Defender Firewall is active on Domain and Private profiles.",
        options: [
          { label: "Enabled on both profiles", status: "PASS" },
          { label: "Enabled on only one profile", status: "WARN" },
          { label: "Disabled on both profiles", status: "FAIL" }
        ],
        selected: 0,
        status: "PASS",
        remediation: "Enable Windows Defender Firewall on Domain and Private network profiles.",
        fixCmd: "Set-NetFirewallProfile -Profile Domain,Private -Enabled True"
      },
      {
        id: "fw-2",
        name: "Public Network Profile Protection",
        desc: "Ensure the Public profile is enabled and blocks unsolicited inbound traffic.",
        options: [
          { label: "Enabled & blocking inbound", status: "PASS" },
          { label: "Enabled with broad exceptions", status: "WARN" },
          { label: "Disabled on Public profile", status: "FAIL" }
        ],
        selected: 0,
        status: "PASS",
        remediation: "Enable the Public firewall profile and set default inbound action to Block.",
        fixCmd: "Set-NetFirewallProfile -Profile Public -Enabled True -DefaultInboundAction Block"
      },
      {
        id: "fw-3",
        name: "Default Inbound Action Policy",
        desc: "Block unsolicited inbound connections by default across firewall profiles.",
        options: [
          { label: "Block inbound by default", status: "PASS" },
          { label: "Allow inbound on selected profile", status: "FAIL" }
        ],
        selected: 0,
        status: "PASS",
        remediation: "Set default inbound action to Block on all firewall profiles.",
        fixCmd: "Set-NetFirewallProfile -All -DefaultInboundAction Block"
      },
      {
        id: "fw-4",
        name: "Inbound Firewall Rules & Exposed Ports",
        desc: "Review active inbound rules to ensure high-risk ports (such as RDP/SMB) are restricted.",
        options: [
          { label: "Minimal rules; high-risk ports restricted", status: "PASS" },
          { label: "Remote management open to subnet", status: "WARN" },
          { label: "Unrestricted inbound rules present", status: "FAIL" }
        ],
        selected: 0,
        status: "PASS",
        remediation: "Audit enabled inbound rules and restrict remote access ports to trusted hosts.",
        fixCmd: "Get-NetFirewallRule -Enabled True -Direction Inbound | Where-Object Action -eq 'Allow'"
      }
    ]
  },
  {
    id: "system",
    number: "04",
    title: "System Configuration",
    summary: "Windows updates, antivirus, UAC and other security configurations.",
    probeCmd: "Get-MpComputerStatus | Select AntivirusEnabled,RealTimeProtectionEnabled; (Get-ItemProperty HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System).EnableLUA",
    probeOutput: [
      "AntivirusEnabled        : True",
      "RealTimeProtectionEnabled : True",
      "EnableLUA (UAC)         : 1"
    ],
    controls: [
      {
        id: "sys-1",
        name: "Windows Update & Patch Currency",
        desc: "Verify security updates are installed and pending update checks are current.",
        options: [
          { label: "Up to date (no critical patches missing)", status: "PASS" },
          { label: "Pending reboot or minor updates", status: "WARN" },
          { label: "Outdated / updates disabled", status: "FAIL" }
        ],
        selected: 0,
        status: "PASS",
        remediation: "Install latest Windows security updates and restart the VM if required.",
        fixCmd: "UsoClient StartInteractiveScan"
      },
      {
        id: "sys-2",
        name: "Antivirus & Real-Time Protection",
        desc: "Confirm Microsoft Defender / endpoint antivirus and real-time scanning are active.",
        options: [
          { label: "Active with real-time protection", status: "PASS" },
          { label: "Installed but definitions stale", status: "WARN" },
          { label: "Disabled or missing", status: "FAIL" }
        ],
        selected: 0,
        status: "PASS",
        remediation: "Enable real-time protection and update antivirus definitions.",
        fixCmd: "Set-MpPreference -DisableRealtimeMonitoring $false; Update-MpSignature"
      },
      {
        id: "sys-3",
        name: "User Account Control (UAC)",
        desc: "Ensure UAC is enabled (EnableLUA = 1) to prompt before elevated actions.",
        options: [
          { label: "Enabled (EnableLUA = 1)", status: "PASS" },
          { label: "Disabled (EnableLUA = 0)", status: "FAIL" }
        ],
        selected: 0,
        status: "PASS",
        remediation: "Enable User Account Control by setting EnableLUA to 1.",
        fixCmd: "Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System' -Name 'EnableLUA' -Value 1"
      },
      {
        id: "sys-4",
        name: "Remote Desktop & Legacy Service Hardening",
        desc: "Check that unnecessary remote services or SMBv1 are disabled on the VM.",
        options: [
          { label: "Hardened (SMBv1 off, RDP controlled)", status: "PASS" },
          { label: "RDP enabled without NLA", status: "WARN" },
          { label: "SMBv1 or risky legacy service active", status: "FAIL" }
        ],
        selected: 0,
        status: "PASS",
        remediation: "Disable SMBv1 protocol and enforce Network Level Authentication (NLA) if RDP is used.",
        fixCmd: "Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart"
      }
    ]
  }
];

let state = {
  currentPage: "landing",
  activeDomainId: "privileges",
  domains: JSON.parse(JSON.stringify(ASSESSMENT_DOMAINS)),
  probeLogs: {}
};

function getVmMeta() {
  return {
    hostname: document.getElementById("vm-hostname")?.value.trim() || "WIN11-VM-AUDIT01",
    os: document.getElementById("vm-os")?.value.trim() || "Windows 11 Pro (23H2)",
    hypervisor: document.getElementById("vm-hypervisor")?.value || "VMware Workstation",
    assessor: document.getElementById("vm-assessor")?.value.trim() || "Auditor",
    date: new Date().toLocaleDateString("en-GB", { day: "2-digit", month: "short", year: "numeric" })
  };
}

function getControlPoints(status) {
  if (status === "PASS") return 100;
  if (status === "WARN") return 50;
  if (status === "FAIL") return 0;
  return null;
}

function getDomainStats(domain) {
  const evaluated = domain.controls.filter((c) => getControlPoints(c.status) !== null);
  const totalPoints = evaluated.reduce((sum, c) => sum + getControlPoints(c.status), 0);
  const score = evaluated.length ? Math.round(totalPoints / evaluated.length) : 0;
  return {
    evaluatedCount: evaluated.length,
    totalCount: domain.controls.length,
    score
  };
}

function getOverallAudit() {
  const allControls = state.domains.flatMap((d) => d.controls);
  const evaluated = allControls.filter((c) => getControlPoints(c.status) !== null);
  const totalPoints = evaluated.reduce((sum, c) => sum + getControlPoints(c.status), 0);
  const score = evaluated.length ? Math.round(totalPoints / evaluated.length) : 0;
  const weaknesses = allControls.filter((c) => c.status === "FAIL" || c.status === "WARN");
  return {
    evaluatedCount: evaluated.length,
    totalCount: allControls.length,
    score,
    weaknesses
  };
}

function updateTopProgress() {
  const overall = getOverallAudit();
  const el = document.getElementById("global-progress");
  if (el) el.textContent = `${overall.evaluatedCount}/${overall.totalCount}`;
}

function navigateTo(pageName) {
  state.currentPage = pageName;
  document.querySelectorAll(".page").forEach((p) => p.classList.remove("active"));

  const targetId = pageName === "workspace" ? "page-workspace" : `page-${pageName}`;
  document.getElementById(targetId)?.classList.add("active");

  document.querySelectorAll(".step-btn").forEach((b) => b.classList.remove("active"));
  if (pageName === "landing") document.getElementById("nav-landing")?.classList.add("active");
  if (pageName === "hub" || pageName === "workspace") document.getElementById("nav-hub")?.classList.add("active");
  if (pageName === "report") document.getElementById("nav-report")?.classList.add("active");

  if (pageName === "hub") renderHub();
  if (pageName === "workspace") renderWorkspace();
  if (pageName === "report") renderReport();

  updateTopProgress();
  window.scrollTo({ top: 0, behavior: "smooth" });
}

function startAssessment() {
  const consent = document.getElementById("auth-consent")?.checked;
  const errEl = document.getElementById("consent-error");
  if (!consent) {
    errEl?.classList.remove("hidden");
    return;
  }
  errEl?.classList.add("hidden");
  navigateTo("hub");
}

function openAssessment(domainId) {
  state.activeDomainId = domainId;
  navigateTo("workspace");
}

function loadSampleBaseline(mode) {
  state.domains = JSON.parse(JSON.stringify(ASSESSMENT_DOMAINS));
  if (mode === "unhardened") {
    state.domains.forEach((domain) => {
      domain.controls.forEach((ctrl, idx) => {
        if (ctrl.options.length === 3) {
          ctrl.selected = idx % 2 === 0 ? 2 : 1;
        } else {
          ctrl.selected = 1;
        }
        ctrl.status = ctrl.options[ctrl.selected].status;
      });
    });
  }
  renderHub();
  updateTopProgress();
}

function renderHub() {
  const grid = document.getElementById("domains-grid");
  if (!grid) return;

  grid.innerHTML = state.domains
    .map((domain) => {
      const stats = getDomainStats(domain);
      return `
        <div class="domain-card" onclick="openAssessment('${domain.id}')">
          <div>
            <div class="domain-top">
              <span class="domain-num">SECURITY AREA</span>
              <span class="domain-score">${stats.score}%</span>
            </div>
            <h3>${domain.title}</h3>
            <p>${domain.summary}</p>
            <div class="progress-bar">
              <div class="progress-fill" style="width: ${stats.score}%"></div>
            </div>
          </div>
          <div class="domain-footer">
            <span>${stats.evaluatedCount}/${stats.totalCount} checks evaluated</span>
            <span>Open Assessment &rarr;</span>
          </div>
        </div>
      `;
    })
    .join("");
}

function renderWorkspace() {
  const domain = state.domains.find((d) => d.id === state.activeDomainId) || state.domains[0];
  state.activeDomainId = domain.id;

  const pillsEl = document.getElementById("workspace-pills");
  if (pillsEl) {
    pillsEl.innerHTML = state.domains
      .map(
        (d) => `
        <button
          class="switcher-pill ${d.id === domain.id ? "active" : ""}"
          onclick="openAssessment('${d.id}')"
        >
          ${d.title}
        </button>
      `
      )
      .join("");
  }

  const stats = getDomainStats(domain);
  const logText =
    state.probeLogs[domain.id] ||
    `PS C:\\> ${domain.probeCmd}\nClick "Run Simulated Check" to inspect sample ${domain.title.toLowerCase()} output for this VM.`;

  const contentEl = document.getElementById("workspace-content");
  if (!contentEl) return;

  contentEl.innerHTML = `
    <div class="workspace-header">
      <div>
        <h2>${domain.title}</h2>
        <p style="color: var(--muted); font-size: 0.92rem;">${domain.summary}</p>
      </div>
      <div style="text-align: right;">
        <div style="font-size: 0.8rem; color: var(--muted);">Area Score</div>
        <div style="font-size: 1.6rem; font-weight: 800; color: var(--primary);">${stats.score}%</div>
      </div>
    </div>

    <div class="probe-box">
      <div class="probe-bar">
        <span>Diagnostic Reference Command</span>
        <button class="btn-sm" onclick="runDomainProbe('${domain.id}')">Run Simulated Check</button>
      </div>
      <div class="probe-output">${escapeHtml(logText)}</div>
    </div>

    <div class="controls-list">
      ${domain.controls
        .map(
          (ctrl, cIdx) => `
        <div class="control-item">
          <div class="control-meta">
            <h4>${ctrl.name}</h4>
            <p>${ctrl.desc}</p>
          </div>
          <div class="control-actions">
            <select class="control-select" onchange="selectControlOption('${domain.id}', ${cIdx}, this.value)">
              ${ctrl.options
                .map(
                  (opt, oIdx) => `
                <option value="${oIdx}" ${ctrl.selected === oIdx ? "selected" : ""}>
                  ${opt.label}
                </option>
              `
                )
                .join("")}
            </select>
            <span class="status-pill status-${ctrl.status}">${ctrl.status}</span>
          </div>
        </div>
      `
        )
        .join("")}
    </div>

    <div class="workspace-footer">
      <button class="btn-secondary" onclick="navigateTo('hub')">&larr; Back to Assessments</button>
      <button class="btn-primary" onclick="goToNextDomainOrReport('${domain.id}')">
        ${getNextButtonLabel(domain.id)}
      </button>
    </div>
  `;
}

function runDomainProbe(domainId) {
  const domain = state.domains.find((d) => d.id === domainId);
  if (!domain) return;
  const vm = getVmMeta();
  state.probeLogs[domainId] = [
    `[${vm.hostname}] PS> ${domain.probeCmd}`,
    "------------------------------------------------------------",
    ...domain.probeOutput
  ].join("\n");
  renderWorkspace();
}

function selectControlOption(domainId, controlIdx, optionIdxStr) {
  const domain = state.domains.find((d) => d.id === domainId);
  if (!domain) return;
  const ctrl = domain.controls[controlIdx];
  const oIdx = Number(optionIdxStr);
  ctrl.selected = oIdx;
  ctrl.status = ctrl.options[oIdx].status;
  updateTopProgress();
  renderWorkspace();
}

function getNextButtonLabel(currentId) {
  const idx = state.domains.findIndex((d) => d.id === currentId);
  if (idx >= 0 && idx < state.domains.length - 1) {
    return `Next: ${state.domains[idx + 1].title} \u2192`;
  }
  return "Generate Final Audit Report \u2192";
}

function goToNextDomainOrReport(currentId) {
  const idx = state.domains.findIndex((d) => d.id === currentId);
  if (idx >= 0 && idx < state.domains.length - 1) {
    openAssessment(state.domains[idx + 1].id);
  } else {
    navigateTo("report");
  }
}

function renderReport() {
  const el = document.getElementById("report-content");
  if (!el) return;

  const vm = getVmMeta();
  const overall = getOverallAudit();

  const weaknessesHtml = overall.weaknesses.length
    ? overall.weaknesses
        .map(
          (w) => `
        <div class="finding-card ${w.status === "WARN" ? "warn" : ""}">
          <strong>[${w.status}] ${w.name}</strong>
          <p style="font-size: 0.88rem; color: var(--muted); margin-top: 0.2rem;">
            Observed: ${w.options[w.selected].label}
          </p>
          <p style="font-size: 0.88rem; margin-top: 0.35rem;">
            <strong>Recommendation:</strong> ${w.remediation}
          </p>
          <code>${escapeHtml(w.fixCmd)}</code>
        </div>
      `
        )
        .join("")
    : `<p style="color: var(--pass); font-weight: 600;">No security weaknesses or warnings detected across the four assessment areas.</p>`;

  const rowsHtml = state.domains
    .flatMap((d) =>
      d.controls.map(
        (c) => `
        <tr>
          <td>${d.title}</td>
          <td>${c.name}</td>
          <td>${c.options[c.selected].label}</td>
          <td><span class="status-pill status-${c.status}">${c.status}</span></td>
        </tr>
      `
      )
    )
    .join("");

  el.innerHTML = `
    <div class="report-card">
      <div class="report-top">
        <div>
          <h2>Windows Security Audit Report</h2>
          <p style="color: var(--muted); font-size: 0.9rem;">
            Target VM: <strong>${escapeHtml(vm.hostname)}</strong> (${escapeHtml(vm.os)}) &bull;
            Hypervisor: <strong>${escapeHtml(vm.hypervisor)}</strong> &bull;
            Auditor: <strong>${escapeHtml(vm.assessor)}</strong> &bull;
            Date: <strong>${vm.date}</strong>
          </p>
        </div>
        <div class="score-box">
          <div style="font-size: 0.8rem; color: var(--muted);">Overall Security Score</div>
          <div class="score-number">${overall.score}%</div>
        </div>
      </div>

      <div class="summary-grid">
        ${state.domains
          .map((d) => {
            const s = getDomainStats(d);
            return `
            <div class="stat-box">
              <span>${d.title}</span>
              <strong>${s.score}%</strong>
            </div>
          `;
          })
          .join("")}
      </div>

      <div class="export-bar">
        <button class="btn-primary" onclick="window.print()">Print / Save as PDF</button>
        <button class="btn-secondary" onclick="downloadTextReport()">Download Audit Report (.TXT)</button>
        <button class="btn-secondary" onclick="downloadHtmlReport()">Download Audit Report (.HTML)</button>
        <button class="btn-secondary" onclick="navigateTo('hub')">Back to Assessments</button>
      </div>
    </div>

    <div class="report-card">
      <h3>Identified Weaknesses & Recommendations (${overall.weaknesses.length})</h3>
      <p style="color: var(--muted); font-size: 0.88rem; margin-bottom: 1rem;">
        Actionable hardening steps for non-compliant or warning configurations found during the assessment.
      </p>
      ${weaknessesHtml}
    </div>

    <div class="report-card">
      <h3>Complete Assessment Summary</h3>
      <table class="report-table">
        <thead>
          <tr>
            <th>Assessment Area</th>
            <th>Control</th>
            <th>Observed State</th>
            <th>Status</th>
          </tr>
        </thead>
        <tbody>${rowsHtml}</tbody>
      </table>
    </div>
  `;
}

function buildPlainTextReport() {
  const vm = getVmMeta();
  const overall = getOverallAudit();
  const lines = [
    "WINDOWS SECURITY AUDIT REPORT - SECUREAUDIT (PROJECT 09)",
    "=========================================================",
    `Target VM Hostname : ${vm.hostname}`,
    `Operating System   : ${vm.os}`,
    `Hypervisor         : ${vm.hypervisor}`,
    `Auditor            : ${vm.assessor}`,
    `Date               : ${vm.date}`,
    `Overall Score      : ${overall.score}% (${overall.evaluatedCount}/${overall.totalCount} checks evaluated)`,
    "",
    "AREA SCORES:",
    ...state.domains.map((d) => `- ${d.title}: ${getDomainStats(d).score}%`),
    "",
    "IDENTIFIED WEAKNESSES & RECOMMENDATIONS:",
    ...(overall.weaknesses.length
      ? overall.weaknesses.flatMap((w) => [
          `[${w.status}] ${w.name} (${w.options[w.selected].label})`,
          `  Recommendation: ${w.remediation}`,
          `  Command       : ${w.fixCmd}`
        ])
      : ["None identified."]),
    "",
    "DETAILED CONTROL RESULTS:",
    ...state.domains.flatMap((d) =>
      d.controls.map(
        (c) => `- [${c.status}] ${d.title} | ${c.name}: ${c.options[c.selected].label}`
      )
    )
  ];
  return lines.join("\n");
}

function downloadTextReport() {
  const vm = getVmMeta();
  const blob = new Blob([buildPlainTextReport()], { type: "text/plain;charset=utf-8" });
  triggerDownload(blob, `Windows-Security-Audit-${vm.hostname}.txt`);
}

function downloadHtmlReport() {
  const vm = getVmMeta();
  const reportBody = document.getElementById("report-content")?.innerHTML || "";
  const htmlDoc = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <title>Windows Security Audit Report - ${escapeHtml(vm.hostname)}</title>
  <style>
    body { font-family: Segoe UI, sans-serif; max-width: 960px; margin: 2rem auto; padding: 0 1rem; color: #0f172a; }
    .report-card { border: 1px solid #cbd5e1; border-radius: 10px; padding: 1.5rem; margin-bottom: 1.2rem; }
    .summary-grid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 0.75rem; margin: 1rem 0; }
    .stat-box { background: #f8fafc; border: 1px solid #e2e8f0; border-radius: 8px; padding: 0.8rem; }
    .finding-card { border-left: 4px solid #b91c1c; background: #f8fafc; padding: 0.8rem 1rem; margin-bottom: 0.7rem; }
    .finding-card.warn { border-left-color: #b45309; }
    code { display: block; background: #0f172a; color: #a7f3d0; padding: 0.45rem; border-radius: 6px; margin-top: 0.4rem; }
    table { width: 100%; border-collapse: collapse; margin-top: 0.75rem; }
    th, td { border-bottom: 1px solid #e2e8f0; padding: 0.55rem; text-align: left; }
    .export-bar { display: none; }
  </style>
</head>
<body>${reportBody}</body>
</html>`;
  const blob = new Blob([htmlDoc], { type: "text/html;charset=utf-8" });
  triggerDownload(blob, `Windows-Security-Audit-${vm.hostname}.html`);
}

function triggerDownload(blob, filename) {
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}

function escapeHtml(str) {
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

// Initial render
updateTopProgress();
renderHub();