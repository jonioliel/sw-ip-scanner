(() => {
  'use strict';
  const root = document.getElementById('ip-scanner');
  const api = window.IPScannerTransport;
  const ui = name => root.querySelector(`[data-ui="${name}"]`);
  const action = name => root.querySelector(`[data-action="${name}"]`);
  const statusNames = {occupied: 'תפוסה', known: 'נראתה בעבר', unobserved: 'פנויה לכאורה', unscanned: 'טרם נסרקה'};
  const saved = window.openai?.widgetState?.privateContent || {};
  let tab = ['devices','free','ranges'].includes(saved.tab) ? saved.tab : 'devices';
  let page = 0, mapPage = 0, selectedIP = '', editingIP = '', busy = false, payload = null, polling = null;
  const PAGE_SIZE = 12, MAP_SIZE = 256;
  const search = ui('search'), filter = ui('status-filter');
  search.value = typeof saved.search === 'string' ? saved.search : '';
  const escape = value => String(value ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
  const badge = status => `<span class="status ${status}"><i class="dot ${status}"></i>${statusNames[status]}</span>`;
  function date(value) {
    if (!value) return '—';
    return new Date(value).toLocaleString('he-IL', {day:'2-digit',month:'2-digit',hour:'2-digit',minute:'2-digit'});
  }
  function persist() {
    window.openai?.setWidgetState?.({modelContent:{view:tab}, privateContent:{tab,search:search.value}})?.catch(() => {});
  }
  function error(message) { ui('error').textContent = message || ''; ui('error').hidden = !message; }
  function setTab(value) {
    tab = value; page = 0;
    root.querySelectorAll('[data-tab]').forEach(button => {
      const active = button.dataset.tab === tab;
      button.classList.toggle('active',active); button.setAttribute('aria-pressed',String(active));
    });
    filter.innerHTML = tab === 'free' ? '<option value="all">פנויות לכאורה</option>' :
      '<option value="all">כל המצבים</option><option value="occupied">תפוסות</option><option value="known">נראו בעבר</option>' +
      (tab === 'ranges' ? '<option value="unobserved">פנויות לכאורה</option><option value="unscanned">טרם נסרקו</option>' : '');
    filter.disabled = tab === 'free';
    renderTable();
  }
  function renderTable() {
    if (!payload?.snapshot) return;
    const snapshot = payload.snapshot;
    const query = search.value.trim().toLocaleLowerCase();
    let rows = tab === 'ranges' ? snapshot.ranges : snapshot.rows.filter(row => tab === 'free'
      ? row.status === 'unobserved' : ['occupied','known'].includes(row.status));
    if (filter.value !== 'all') rows = rows.filter(row => row.status === filter.value);
    if (query) rows = rows.filter(row => {
      if (tab === 'ranges') {
        if (selectedIP && query === selectedIP) {
          const number = ipNumber(selectedIP);
          return number >= ipNumber(row.start) && number <= ipNumber(row.end);
        }
        return `${row.start} ${row.end} ${statusNames[row.status]}`.toLowerCase().includes(query);
      }
      return `${row.ip} ${row.name} ${row.hostname} ${row.vendor} ${row.mac}`.toLocaleLowerCase().includes(query);
    });
    const pages = Math.max(1,Math.ceil(rows.length / PAGE_SIZE));
    page = Math.min(page,pages - 1);
    const shown = rows.slice(page * PAGE_SIZE,(page + 1) * PAGE_SIZE);
    const headers = tab === 'ranges' ? ['מכתובת','עד כתובת','כתובות','מצב'] : tab === 'free'
      ? ['כתובת IP','מצב','הערה'] : ['מכשיר','כתובת IP','יצרן / MAC','מצב','נראה לאחרונה',''];
    ui('table-head').innerHTML = `<tr>${headers.map(h => `<th scope="col">${h}</th>`).join('')}</tr>`;
    let html = shown.map(row => {
      if (tab === 'ranges') return `<tr><td class="mono">${escape(row.start)}</td><td class="mono">${escape(row.end)}</td><td>${row.count}</td><td>${badge(row.status)}</td></tr>`;
      if (tab === 'free') return `<tr><td class="mono">${escape(row.ip)}</td><td>${badge(row.status)}</td><td>לא זוהה מכשיר בסריקה האחרונה</td></tr>`;
      return `<tr><td><span class="name">${escape(row.name || 'מכשיר ללא שם')}</span><span class="subtext">${escape(row.hostname || 'אין שם שפורסם ברשת')}</span></td><td class="mono">${escape(row.ip)}</td><td>${escape(row.vendor || 'לא זוהה')}<span class="subtext mono">${escape(row.mac || '—')}</span></td><td>${badge(row.status)}</td><td>${date(row.last_seen)}</td><td><button class="edit-button" data-edit="${escape(row.ip)}" aria-label="עריכת שם ${escape(row.name || row.ip)}">✎</button></td></tr>`;
    }).join('');
    if (!html) html = `<tr><td colspan="${headers.length}" class="empty">${snapshot.scanned_at ? 'לא נמצאו כתובות התואמות לתצוגה. אפשר לשנות את החיפוש או הסינון.' : 'הרשת מוכנה. הפעל סריקה כדי לגלות מכשירים וכתובות פנויות לכאורה.'}</td></tr>`;
    ui('table-body').innerHTML = html;
    ui('result-count').textContent = `${rows.length} ${tab === 'ranges' ? 'טווחים' : 'כתובות'}`;
    ui('page-summary').textContent = rows.length ? `${page*PAGE_SIZE+1}–${Math.min((page+1)*PAGE_SIZE,rows.length)} מתוך ${rows.length}` : 'אין תוצאות';
    ui('page').textContent = `${page+1} / ${pages}`;
    action('prev').disabled = page === 0; action('next').disabled = page >= pages-1;
  }
  function ipNumber(ip) { return ip.split('.').reduce((a,v) => a*256+Number(v),0); }
  function renderMap() {
    const snapshot = payload?.snapshot;
    if (!snapshot) return;
    const pages = Math.ceil(snapshot.rows.length/MAP_SIZE);
    mapPage = Math.min(mapPage,Math.max(0,pages-1));
    const rows = snapshot.rows.slice(mapPage*MAP_SIZE,(mapPage+1)*MAP_SIZE);
    ui('map').innerHTML = rows.map(row => `<button class="${row.status}" data-ip="${row.ip}" aria-pressed="${row.ip === selectedIP}" aria-label="${escape(row.ip + ' · ' + statusNames[row.status] + (row.name ? ' · ' + row.name : ''))}">${row.ip.split('.').at(-1)}</button>`).join('');
    ui('map-prefix').textContent = rows.length ? `${rows[0].ip} – ${rows.at(-1).ip}` : '';
    ui('map-page').textContent = `${mapPage+1} / ${pages}`;
    action('map-prev').disabled = mapPage === 0; action('map-next').disabled = mapPage === pages-1;
  }
  function render(next) {
    payload = next;
    ui('demo').hidden = !next.demo;
    const selector = root.querySelector('#network-select');
    const selected = next.selected?.cidr;
    const networks = [...next.networks];
    if (next.selected && !networks.some(n => n.cidr === selected)) networks.unshift(next.selected);
    const signature = JSON.stringify(networks.map(n => [n.cidr,n.interface,n.supported]));
    if (selector.dataset.signature !== signature) {
      selector.innerHTML = networks.map(n => `<option value="${escape(n.cidr)}" ${n.supported ? '' : 'disabled'}>${escape(n.cidr)}${n.supported ? '' : ' · טווח גדול מדי'}</option>`).join('');
      selector.dataset.signature = signature;
    }
    selector.value = selected || '';
    selector.disabled = next.scan.running || busy;
    ui('interface').textContent = next.selected?.interface || '';
    action('scan').disabled = busy || !next.selected;
    ui('scan-label').textContent = next.scan.running ? 'עצור סריקה' : 'סרוק את הרשת';
    error(next.network_error || next.scan.error);
    const snap = next.snapshot;
    if (!snap) { ui('scan-meta').textContent = 'לא נמצאה רשת לסריקה'; return; }
    for (const name of ['occupied','known','unobserved']) ui(name).textContent = snap.scanned_at ? snap.counts[name] : '—';
    ui('total').textContent = snap.total;
    ui('device-count').textContent = snap.counts.occupied + snap.counts.known;
    ui('free-count').textContent = snap.counts.unobserved;
    const elapsed = Math.max(0,Math.floor(Date.now()/1000-(next.scan.started_at || Date.now()/1000)));
    ui('scan-meta').textContent = next.scan.running
      ? `${next.scan.phase === 'names' ? 'משלים שמות מכשירים' : 'סורק את הרשת'} · ${elapsed} שניות`
      : snap.scanned_at ? `סריקה אחרונה: ${date(snap.scanned_at)} · ${snap.duration} שנ׳` : 'טרם בוצעה סריקה';
    const warning = snap.warnings.join(' · ');
    ui('warning').textContent = warning; ui('warning').hidden = !warning;
    renderMap(); renderTable();
  }
  async function perform(fn) {
    if (busy) return;
    busy = true;
    action('scan').disabled = true;
    try { render(await fn()); } catch (e) { error(e.message); }
    finally { busy = false; action('scan').disabled = !payload?.selected; root.querySelector('#network-select').disabled = !!payload?.scan.running; }
  }
  async function refresh() {
    if (busy) return;
    try { render(await api.state()); } catch (e) { error('אין חיבור לתוסף: ' + e.message); }
  }
  root.addEventListener('click', event => {
    const button = event.target.closest('button');
    if (!button || button.disabled) return;
    if (button.dataset.tab) { setTab(button.dataset.tab); persist(); }
    if (button.dataset.ip) {
      selectedIP = button.dataset.ip; search.value = selectedIP;
      const row = payload.snapshot.rows.find(r => r.ip === selectedIP);
      setTab(row.status === 'unobserved' ? 'free' : row.status === 'unscanned' ? 'ranges' : 'devices');
      ui('selected-ip').textContent = `${selectedIP} · ${statusNames[row.status]}${row.name ? ' · ' + row.name : ''}`;
      renderMap(); persist();
    }
    if (button.dataset.edit) {
      editingIP = button.dataset.edit;
      const row = payload.snapshot.rows.find(r => r.ip === editingIP);
      ui('alias-ip').textContent = editingIP; ui('alias-input').value = row.alias || '';
      ui('alias-error').hidden = true; ui('alias-dialog').showModal();
    }
    switch (button.dataset.action) {
      case 'scan': perform(() => payload.scan.running ? api.stop() : api.scan()); break;
      case 'prev': page--; renderTable(); break;
      case 'next': page++; renderTable(); break;
      case 'map-prev': mapPage--; renderMap(); break;
      case 'map-next': mapPage++; renderMap(); break;
      case 'export': api.export(); break;
      case 'theme': root.style.colorScheme = getComputedStyle(root).colorScheme === 'dark' ? 'light' : 'dark'; break;
      case 'save-alias': {
        button.disabled = true;
        api.alias(editingIP,ui('alias-input').value.trim()).then(next => {
          render(next); ui('alias-dialog').close();
        }).catch(e => { ui('alias-error').textContent = e.message; ui('alias-error').hidden = false; })
          .finally(() => {button.disabled=false;}); break;
      }
    }
  });
  search.addEventListener('input', () => { page=0; selectedIP=''; renderMap(); renderTable(); persist(); });
  filter.addEventListener('change', () => { page=0; renderTable(); });
  root.querySelector('#network-select').addEventListener('change', event => {
    page=0; mapPage=0; selectedIP=''; search.value='';
    perform(() => api.network(event.target.value));
  });
  ui('alias-dialog').querySelector('form').addEventListener('submit', event => {
    if (event.submitter?.value !== 'cancel') { event.preventDefault(); action('save-alias').click(); }
  });
  setTab(tab);
  refresh();
  polling = setInterval(() => { if (!document.hidden && root.isConnected) refresh(); },1500);
  window.addEventListener('pagehide', () => clearInterval(polling));
  window.addEventListener('openai:set_globals', event => {
    const state = event.detail?.globals?.widgetState?.privateContent;
    if (state && ['devices','free','ranges'].includes(state.tab)) {
      search.value = typeof state.search === 'string' ? state.search : ''; setTab(state.tab);
    }
  });
  if (globalThis.Tweak) {
    const design = {density:'נוח', corners:12};
    const tweak = new Tweak({container:root,onChange:() => {
      root.querySelectorAll('.metric,.map-panel,.table-panel,.network-bar').forEach(el => {el.style.borderRadius=`${design.corners}px`;});
      root.querySelectorAll('td').forEach(el => {el.style.paddingBlock=design.density === 'קומפקטי' ? '7px' : '11px';});
    }});
    tweak.addSelect(design,'density',{label:'צפיפות הטבלה',options:['נוח','קומפקטי']});
    tweak.addSlider(design,'corners',{label:'עיגול פינות',min:0,max:20,unit:'px'});
  }
})();
