
// Global State
const TACTICS = [
  { id: "TA0043", name: "Reconnaissance" },
  { id: "TA0042", name: "Resource Development" },
  { id: "TA0001", name: "Initial Access" },
  { id: "TA0002", name: "Execution" },
  { id: "TA0003", name: "Persistence" },
  { id: "TA0004", name: "Privilege Escalation" },
  { id: "TA0005", name: "Defense Evasion" },
  { id: "TA0006", name: "Credential Access" },
  { id: "TA0007", name: "Discovery" },
  { id: "TA0008", name: "Lateral Movement" },
  { id: "TA0009", name: "Collection" },
  { id: "TA0011", name: "Command and Control" },
  { id: "TA0010", name: "Exfiltration" },
  { id: "TA0040", name: "Impact" }
];

// --- DATA STRUCTURE FOR TECHNIQUES ---
// ADD YOUR TECHNIQUES HERE
// The key is the Tactic ID (e.g., TA0001). The value is an array of technique objects.
const TECHNIQUES = {

 "TA0043": [
    {
      id: "T1595",
      name: "Active Scanning",
      description: "Adversaries may perform active scanning to gather information about target systems and networks.",
          subtechniques: ["T1595.001 - Network Scanning", "T1595.002 - Port Scanning"],
      rules: [
        {
          type: "Splunk SPL -T1595.001 ",
          lang: "splunk",
          code: `index=network sourcetype=nmap OR sourcetype=scan`
        },
        {
          type: "Sentinel KQL",
          lang: "sentinel",
          code: `NetworkTraffic | where Protocol == "TCP" and DestinationPort in (22, 80, 443)`
        }
      ]
    },
    {
      id: "T1592",
      name: "Gather Victim Identity Information",
      description: "Adversaries may gather information about the identity of a victim's personnel to plan further operations.",
      rules: [
        {
          type: "Elastic Query",
          lang: "elastic",
          code: `event.category: "identity" AND event.action: "lookup"`
        },
        {
          type: "Sentinel KQL",
          lang: "sentinel",
          code: `IdentityInfo | where Action == "Search"`
        }
      ]
    }
  ],

  // ======================
  // TA0042 – Resource Development
  // ======================
  "TA0042": [
    {
      id: "T1583",
      name: "Acquire Infrastructure",
      description: "Adversaries may acquire infrastructure such as servers, domains, or hosting services to support malicious operations.",
      rules: [
        {
          type: "Splunk SPL",
          lang: "splunk",
          code: `index=infra acquisition OR registration`
        },
        {
          type: "Sentinel KQL",
          lang: "sentinel",
          code: `InfraEvents | where EventType == "Purchase" or EventType == "Registration"`
        }
      ]
    },
    {
      id: "T1584",
      name: "Compromise Infrastructure",
      description: "Adversaries may compromise third-party infrastructure to use in operations such as phishing or command and control.",
      rules: [
        {
          type: "Elastic Query",
          lang: "elastic",
          code: `event.category: "compromise" AND event.type: "third_party"`
        },
        {
          type: "Sentinel KQL",
          lang: "sentinel",
          code: `CompromiseEvents | where TargetType == "ExternalInfrastructure"`
        }
      ]
    }
  ],

  // ======================
  // TA0001 – Initial Access
  // ======================
  "TA0001": [
    {
      id: "T1566",
      name: "Phishing",
      description: "Adversaries may send phishing messages to trick users into divulging credentials or executing malicious payloads.",
      rules: [
        {
          type: "Splunk SPL",
          lang: "splunk",
          code: `index=email subject="*urgent*" OR subject="*invoice*"`
        },
        {
          type: "Sentinel KQL",
          lang: "sentinel",
          code: `EmailEvents | where Subject contains "urgent" or Subject contains "invoice"`
        }
      ]
    },
    {
      id: "T1190",
      name: "Exploit Public-Facing Application",
      description: "Adversaries may exploit vulnerabilities in Internet-facing systems to gain initial access.",
      rules: [
        {
          type: "Elastic Query",
          lang: "elastic",
          code: `event.category: "exploit" AND target.port: 80`
        },
        {
          type: "Sentinel KQL",
          lang: "sentinel",
          code: `WebEvents | where ActionType == "ExploitAttempt"`
        }
      ]
    }
  ],

  // ======================
  // TA0002 – Execution
  // ======================
  "TA0002": [
    {
      id: "T1059",
      name: "Command and Scripting Interpreter",
      description: "Adversaries may abuse command-line interpreters such as PowerShell or Bash to execute malicious commands.",
      rules: [
        {
          type: "Splunk SPL",
          lang: "splunk",
          code: `index=process process_name=powershell.exe OR process_name=bash`
        },
        {
          type: "Sentinel KQL",
          lang: "sentinel",
          code: `DeviceProcessEvents | where ProcessName in ("powershell.exe","bash")`
        }
      ]
    },
    {
      id: "T1204",
      name: "User Execution",
      description: "Adversaries may rely on user interaction to execute malicious files or payloads.",
      rules: [
        {
          type: "Elastic Query",
          lang: "elastic",
          code: `event.category: "execution" AND event.action: "user_initiated"`
        },
        {
          type: "Sentinel KQL",
          lang: "sentinel",
          code: `DeviceProcessEvents | where InitiatedByUser == true`
        }
      ]
    }
  ],

  // ======================
  // TA0003 – Persistence
  // ======================
  "TA0003": [
    {
      id: "T1547",
      name: "Boot or Logon Autostart Execution",
      description: "Adversaries may use registry entries, scheduled tasks, or scripts to maintain persistence through system reboots.",
      rules: [
        {
          type: "Splunk SPL",
          lang: "splunk",
          code: `index=registry path="HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"`
        },
        {
          type: "Sentinel KQL",
          lang: "sentinel",
          code: `RegistryEvents | where Path contains "CurrentVersion\\Run"`
        }
      ]
    },
    {
      id: "T1053",
      name: "Scheduled Task/Job",
      description: "Adversaries may schedule tasks or cron jobs to execute malicious code persistently.",
      rules: [
        {
          type: "Elastic Query",
          lang: "elastic",
          code: `event.category: "scheduled_task"`
        },
        {
          type: "Sentinel KQL",
          lang: "sentinel",
          code: `ScheduledTaskEvents | where TaskAction contains "execute"`
        }
      ]
    }
  ],

  // ======================
  // TA0004 – Privilege Escalation
  // ======================
  "TA0004": [
    {
      id: "T1068",
      name: "Exploitation for Privilege Escalation",
      description: "Adversaries may exploit software vulnerabilities to gain higher-level permissions.",
          subtechniques: ["T1595.001 - Network Scanning", "T1595.002 - Port Scanning"],
      rules: [
        {
          type: "Splunk SPL",
          lang: "splunk",
          code: `index=security EventCode=4672`
        },
        {
          type: "Sentinel KQL",
          lang: "sentinel",
          code: `SecurityEvent | where EventID == 4672`
        }
      ]
    },
    {
      id: "T1548",
      name: "Abuse Elevation Control Mechanism",
      description: "Adversaries may bypass or abuse permissions to elevate privileges, such as UAC bypass.",
      rules: [
        {
          type: "Elastic Query",
          lang: "elastic",
          code: `event.category: "privilege_escalation"`
        },
        {
          type: "Sentinel KQL",
          lang: "sentinel",
          code: `DeviceProcessEvents | where ElevationLevel == "High"`
        }
      ]
    }
  ],

  // ======================
  // TA0005 – Defense Evasion
  // ======================
  "TA0005": [
    {
      id: "T1027",
      name: "Obfuscated/Encrypted Files",
      description: "Adversaries may use obfuscation or encryption to avoid detection of malicious content.",
      rules: [
        {
          type: "Splunk SPL",
          lang: "splunk",
          code: `index=filesystem file_name="*.exe" AND file_hash_algo="SHA256"`
        },
        {
          type: "Sentinel KQL",
          lang: "sentinel",
          code: `DeviceFileEvents | where FileName endswith ".exe"`
        }
      ]
    },
    {
      id: "T1112",
      name: "Modify Registry",
      description: "Adversaries may modify registry keys to alter system behavior and evade defenses.",
      rules: [
        {
          type: "Elastic Query",
          lang: "elastic",
          code: `event.category: "registry_change"`
        },
        {
          type: "Sentinel KQL",
          lang: "sentinel",
          code: `RegistryEvents | where Operation == "SetValue"`
        }
      ]
    }
  ]

};

// DOM Elements
const matrixGrid = document.getElementById('matrix-grid');
const searchInput = document.getElementById('search-input');
const sidebar = document.getElementById('sidebar');
const sidebarOverlay = document.getElementById('sidebar-overlay');

// Icons (SVG strings)
const ICONS = {
  splunk: '<div class="h-2 w-2 rounded-full bg-green-500"></div>',
  elastic: '<div class="h-2 w-2 rounded-full bg-blue-500"></div>',
  sigma: '<div class="h-2 w-2 rounded-full bg-yellow-500"></div>',
  sentinel: '<div class="h-2 w-2 rounded-full bg-purple-500"></div>'
};

// Initialize
document.addEventListener('DOMContentLoaded', async () => {
  if (document.getElementById('matrix-grid')) {
    renderMatrix();
    setupSearch();
  }
  
  if (document.getElementById('community-rules-container')) {
    loadCommunityRules();
  }
  
  if (document.getElementById('json-generator')) {
    setupGenerator();
  }
});

// --- Matrix Functions ---

function renderMatrix() {
  matrixGrid.innerHTML = '';
  
  TACTICS.forEach(tactic => {
    const column = document.createElement('div');
    column.className = 'tactic-column';
    
    const header = document.createElement('div');
    header.className = 'tactic-header';
    header.innerHTML = `
      <div class="tactic-title">${tactic.name}</div>
      <div class="tactic-count">${tactic.id}</div>
    `;
    
    const list = document.createElement('div');
    list.className = 'technique-list';
    
    // Get techniques for this tactic from our manual data
    const tacticTechniques = TECHNIQUES[tactic.id] || [];

    // Render actual techniques
    tacticTechniques.forEach(tech => {
      const card = document.createElement('div');
      card.className = 'technique-card';
      card.style.minHeight = '40px';
      card.onclick = () => openSidebar(tech);
      
      card.innerHTML = `
        <div class="tech-name">${tech.name}</div>
        ${tech.subtechniques && tech.subtechniques.length > 0 ? '<div class="sub-indicator"></div>' : ''}
      `;
      list.appendChild(card);
    });

    // Add one empty slot at the end for demonstration/future use
    const emptyCard = document.createElement('div');
    emptyCard.className = 'technique-card';
    emptyCard.style.minHeight = '40px';
    emptyCard.style.display = 'flex';
    emptyCard.style.alignItems = 'center';
    emptyCard.style.justifyContent = 'center';
    emptyCard.style.color = '#ccc';
    emptyCard.style.border = '1px dashed #eee';
    emptyCard.style.backgroundColor = '#fafafa';
    emptyCard.innerHTML = `<span style="font-size:0.7rem; font-style:italic;">+ Add</span>`;
    emptyCard.onclick = () => {
       alert(`To add a technique to ${tactic.name}, edit the TECHNIQUES object in script.js under key "${tactic.id}"`);
    };
    list.appendChild(emptyCard);
    
    column.appendChild(header);
    column.appendChild(list);
    matrixGrid.appendChild(column);
  });
}

function setupSearch() {
  searchInput.addEventListener('input', (e) => {
    // Simple search logic
    const query = e.target.value.toLowerCase();
    document.querySelectorAll('.technique-card').forEach(card => {
      if (card.innerText.toLowerCase().includes(query)) {
        card.style.opacity = '1';
      } else {
        card.style.opacity = '0.2';
      }
    });
  });
}

// --- Sidebar Functions ---

function openSidebar(technique) {
  // Populate Sidebar
  document.getElementById('sb-title').textContent = technique.name || "Technique Name";
  document.getElementById('sb-id').textContent = technique.id || "TXXXX";
  document.getElementById('sb-desc').textContent = technique.description || "Description...";
  
  // Subtechniques
  const subContainer = document.getElementById('sb-subtechniques');
  subContainer.innerHTML = '';
  if (technique.subtechniques && technique.subtechniques.length > 0) {
    technique.subtechniques.forEach(sub => {
      const span = document.createElement('span');
      span.className = 'badge';
      span.textContent = sub;
      subContainer.appendChild(span);
    });
  } else {
    subContainer.innerHTML = '<span class="text-muted text-sm">Prova</span>';
  }

  // Render Rules
  renderRules(technique.rules || []);

  // Show
  sidebar.classList.add('open');
  sidebarOverlay.classList.add('open');
}

function closeSidebar() {
  sidebar.classList.remove('open');
  sidebarOverlay.classList.remove('open');
}

function switchTab(tabName) {
  // Buttons
  document.querySelectorAll('.tab-btn').forEach(btn => {
    btn.classList.remove('active');
    if (btn.dataset.tab === tabName) btn.classList.add('active');
  });
  
  // Content
  document.querySelectorAll('.tab-content').forEach(content => {
    content.classList.remove('active');
    if (content.id === `tab-${tabName}`) content.classList.add('active');
  });
}

function renderRules(rules) {
  const container = document.getElementById('sb-rules-list');
  
  if (!rules || rules.length === 0) {
    container.innerHTML = '<p class="text-muted">No rules defined for this technique.</p>';
    return;
  }

  container.innerHTML = rules.map(rule => `
    <div class="rule-block mb-6">
      <h4 class="font-semibold flex items-center gap-2 text-sm mb-2">
        ${ICONS[rule.lang] || ''} ${rule.type}
      </h4>
      <div class="code-block">
        <span class="code-lang">${rule.lang}</span>
        <pre>${rule.code}</pre>
      </div>
    </div>
  `).join('');
}

// --- Community Functions ---

async function loadCommunityRules() {
  const container = document.getElementById('community-rules-container');
  try {
    let rules = [];
    try {
      const res = await fetch('./data/community-rules.json');
      const data = await res.json();
      if (Array.isArray(data) && data.length > 0) rules = data;
    } catch (e) {
      console.error("Error fetching community rules", e);
    }

    if (rules.length === 0) {
      container.innerHTML = `
        <div style="grid-column:1/-1; text-align:center; padding:40px; color:#999; border:2px dashed #eee; border-radius:8px;">
          <h3>No Rules Yet</h3>
          <p>Contribute by adding rules to /data/community-rules</p>
        </div>
      `;
      return;
    }

    window.communityRules = rules;

    container.innerHTML = rules.map((rule, index) => `
      <div class="card" data-index="${index}">
        <div class="card-header">
          <span class="badge primary">${rule.mitre_id}</span>
          <h3>${rule.title}</h3>
          <div style="font-size:0.8rem; color:var(--text-muted);">by ${rule.author}</div>
        </div>
        <div class="card-body">
          <div style="display:flex; gap:5px; flex-wrap:wrap; margin-bottom:15px;">
            ${rule.siem_tags.map(tag => `<span class="badge">${tag}</span>`).join('')}
          </div>
          <button class="btn btn-outline view-rule-btn" style="width:100%">View Rule</button>
        </div>
      </div>
    `).join('');

    container.querySelectorAll('.view-rule-btn').forEach(btn => {
      btn.addEventListener('click', e => {
        const card = e.target.closest('.card');
        const index = card.dataset.index;
        openCommunitySidebar(parseInt(index));
      });
    });

  } catch (err) {
    console.error(err);
    container.innerHTML = 'Error loading community rules.';
  }
}

function openCommunitySidebar(index) {
  const rule = window.communityRules[index];
  const sidebar = document.getElementById('community-sidebar');
  const overlay = document.getElementById('community-sidebar-overlay');

  if (!rule || !sidebar) return;

  sidebar.querySelector('#sb-title').textContent = rule.title || "Rule Title";
  sidebar.querySelector('#sb-id').textContent = rule.mitre_id || "TXXXX";
  sidebar.querySelector('#sb-desc').textContent = rule.details || "No details available";

  const subContainer = sidebar.querySelector('#sb-subtechniques');
  subContainer.innerHTML = '';
  if (rule.subtechniques && rule.subtechniques.length) {
    rule.subtechniques.forEach(sub => {
      const span = document.createElement('span');
      span.className = 'badge';
      span.textContent = sub;
      subContainer.appendChild(span);
    });
  } else {
    subContainer.innerHTML = '<span class="text-muted text-sm">None</span>';
  }

  const codeContainer = sidebar.querySelector('#sb-rules-list');
  codeContainer.innerHTML = '';
  if (rule.rules && Array.isArray(rule.rules)) {
    rule.rules.forEach(c => {
      const block = document.createElement('div');
      block.className = 'rule-block mb-4';
      block.innerHTML = `
        <h4 class="font-semibold flex items-center gap-2 text-sm mb-2">
          ${c.lang ? c.lang.toUpperCase() : ''} ${c.type}
        </h4>
        <div class="code-block">
          <span class="code-lang">${c.lang}</span>
          <pre>${c.code}</pre>
        </div>
      `;
      codeContainer.appendChild(block);
    });
  }

  sidebar.classList.add('open');
  overlay.classList.add('open');
}

function closeSidebar() {
  const sidebar = document.getElementById('community-sidebar');
  const overlay = document.getElementById('community-sidebar-overlay');
  if (!sidebar || !overlay) return;
  sidebar.classList.remove('open');
  overlay.classList.remove('open');
}

loadCommunityRules();


// --- Generator Functions ---

function setupGenerator() {
  const btn = document.getElementById('generate-btn');
  btn.onclick = () => {
    const data = {
      mitre_id: document.getElementById('in-id').value,
      title: document.getElementById('in-title').value,
      author: document.getElementById('in-author').value,
      siem_type: document.getElementById('in-siem').value,
      rule_content: document.getElementById('in-content').value
    };
    
    const json = JSON.stringify(data, null, 2);
    document.getElementById('out-json').textContent = json;
  };
}

// Global expose for onclicks
window.closeSidebar = closeSidebar;
window.switchTab = switchTab;


