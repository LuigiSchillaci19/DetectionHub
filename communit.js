// --- DOM ELEMENTS ---
const container = document.getElementById('community-rules-container');
const sidebar = document.getElementById('community-sidebar');
const overlay = document.getElementById('community-sidebar-overlay');

// --- DOM CONTENT LOADED ---
document.addEventListener('DOMContentLoaded', () => {
  if (container) loadCommunityRules();
});

// --- LOAD COMMUNITY RULES ---
async function loadCommunityRules() {
  try {
    const res = await fetch('./data/community-rules.json');
    const data = await res.json();

    if (!Array.isArray(data) || !data.length) {
      container.innerHTML = `
        <div style="grid-column:1/-1; text-align:center; padding:40px; color:#999; border:2px dashed #eee; border-radius:8px;">
          <h3>No Rules Yet</h3>
          <p>Contribute by adding rules to /data/community-rules</p>
        </div>
      `;
      return;
    }

    window.communityRules = data;

    // --- RENDER CARDS ---
    container.innerHTML = data.map((rule, index) => `
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

    // --- OPEN SIDEBAR BUTTONS ---
    container.querySelectorAll('.view-rule-btn').forEach(btn => {
      btn.addEventListener('click', e => {
        const card = e.target.closest('.card');
        openSidebarCommunity(parseInt(card.dataset.index));
      });
    });

    // --- SEARCH FUNCTION ---
    const input = document.getElementById('search-input-community');
    if (input) {
      input.addEventListener('input', e => {
        const query = e.target.value.toLowerCase();

        container.querySelectorAll('.card').forEach(card => {
          const mitreId = card.querySelector('.badge')?.textContent.toLowerCase() || '';
          const title = card.querySelector('h3')?.textContent.toLowerCase() || '';

          if (!query || mitreId.includes(query) || title.includes(query)) {
            card.style.display = 'block';
          } else {
            card.style.display = 'none';
          }
        });
      });
    }

  } catch(e) {
    console.error(e);
    container.innerHTML = 'Error loading rules';
  }
}

// --- OPEN SIDEBAR ---
function openSidebarCommunity(index) {
  const rule = window.communityRules[index];
  if (!rule || !sidebar || !overlay) return;

  sidebar.querySelector('#sb-title').textContent = rule.title;
  sidebar.querySelector('#sb-id').textContent = rule.mitre_id;
  sidebar.querySelector('#sb-desc').textContent = rule.details || '';

  // Subtechniques
  const sub = sidebar.querySelector('#sb-subtechniques');
  sub.innerHTML = rule.subtechniques?.map(s => `<span class="badge">${s}</span>`).join('') || '<span class="text-muted">None</span>';

  // Rules list
  const containerRules = sidebar.querySelector('#sb-rules-list');
  containerRules.innerHTML = rule.rules?.map(r => `
    <div class="rule-block mb-4">
      <h4 class="font-semibold flex items-center gap-2 text-sm mb-2">${r.lang?.toUpperCase() || ''} ${r.type}</h4>
      <div class="code-block">
        <span class="code-lang">${r.lang}</span>
        <pre>${r.code}</pre>
      </div>
    </div>
  `).join('') || '<p class="text-muted">No rules</p>';

  // Mostra sidebar e overlay
  sidebar.classList.add('open');
  overlay.classList.add('open');

  // Click sull'overlay chiude sidebar
  overlay.addEventListener('click', closeSidebarCommunity);
}

// --- CLOSE SIDEBAR ---
function closeSidebarCommunity() {
  if (!sidebar || !overlay) return;
  sidebar.classList.remove('open');
  overlay.classList.remove('open');
}

// --- GLOBAL ACCESS ---
window.closeSidebarCommunity = closeSidebarCommunity;
	