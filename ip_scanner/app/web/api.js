(() => {
  async function request(path, body) {
    const response = await fetch(new URL(path, document.baseURI), body === undefined ? {cache: 'no-store'} : {
      method: 'POST', headers: {'Content-Type': 'application/json', 'X-IP-Scanner': '1'}, body: JSON.stringify(body)
    });
    const result = await response.json();
    if (!response.ok) throw new Error(result.error || 'הבקשה נכשלה');
    return result;
  }
  window.IPScannerTransport = {
    state: () => request('api/state'),
    scan: () => request('api/scan', {}),
    stop: () => request('api/stop', {}),
    network: cidr => request('api/network', {cidr}),
    alias: (ip, alias) => request('api/alias', {ip, alias}),
    export: () => { const a = document.createElement('a'); a.href = new URL('api/export.csv', document.baseURI); a.download = 'ip-scanner.csv'; a.click(); }
  };
})();
