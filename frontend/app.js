(() => {
  const form = document.getElementById('scan-form');
  const input = document.getElementById('url-input');
  const button = document.getElementById('scan-button');
  const result = document.getElementById('result');
  const errorBox = document.getElementById('error');
  const labels = {
    url_length: 'URL length', dot_count: 'Dots', hyphen_count: 'Hyphens', digit_count: 'Digits',
    special_char_count: 'Special characters', has_https: 'HTTPS', is_ip_address: 'IP address host',
    subdomain_count: 'Subdomains', suspicious_keyword_count: 'Suspicious words', domain_length: 'Domain length',
    path_length: 'Path length', parameter_count: 'Parameters', has_at_symbol: '@ symbol',
    url_entropy: 'URL entropy', is_shortened: 'Shortened URL'
  };

  function safeHistory() {
    try {
      const data = JSON.parse(localStorage.getItem('phishguard-history') || '[]');
      return Array.isArray(data) ? data : [];
    } catch (_) {
      return [];
    }
  }

  function renderHistory() {
    const history = document.getElementById('history');
    const items = safeHistory();
    history.replaceChildren();
    if (!items.length) {
      const empty = document.createElement('p');
      empty.className = 'empty';
      empty.textContent = 'Your recent scans will appear here.';
      history.appendChild(empty);
      return;
    }
    items.forEach(item => {
      const row = document.createElement('div');
      row.className = 'history-item';
      const url = document.createElement('span');
      url.className = 'history-url';
      url.title = String(item.url || '');
      url.textContent = String(item.url || '');
      const score = document.createElement('span');
      score.className = 'history-score';
      score.textContent = `${Math.round(Number(item.score || 0) * 100)}%`;
      const status = document.createElement('span');
      status.className = `history-status${item.bad ? ' bad' : ''}`;
      status.textContent = item.bad ? 'PHISHING' : 'SAFE';
      row.append(url, score, status);
      history.appendChild(row);
    });
  }

  function showError(message) {
    errorBox.textContent = message;
    errorBox.hidden = false;
    result.hidden = true;
  }

  function showFeatures(features) {
    const grid = document.getElementById('features');
    grid.replaceChildren();
    Object.entries(features || {}).forEach(([key, value]) => {
      const item = document.createElement('div');
      item.className = 'feature';
      const name = document.createElement('span');
      name.textContent = labels[key] || key;
      const val = document.createElement('b');
      val.textContent = typeof value === 'number' ? (Number.isInteger(value) ? String(value) : value.toFixed(3)) : String(value);
      item.append(name, val);
      grid.appendChild(item);
    });
  }

  form.addEventListener('submit', async event => {
    event.preventDefault();
    errorBox.hidden = true;
    result.hidden = true;
    button.disabled = true;
    button.firstElementChild.textContent = 'Scanning…';
    try {
      const response = await fetch('/predict', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'Accept': 'application/json' },
        body: JSON.stringify({ url: input.value })
      });
      const data = await response.json();
      if (!response.ok) throw new Error(data.error || `Scan failed (HTTP ${response.status}).`);
      const score = Number(data.phishing_probability);
      if (!Number.isFinite(score)) throw new Error('The server returned an invalid prediction.');
      const isPhishing = data.prediction === 'Phishing';
      document.getElementById('verdict').textContent = isPhishing ? 'Potential phishing' : 'No obvious phishing signals';
      document.getElementById('verdict').style.color = isPhishing ? 'var(--red)' : 'var(--mint)';
      document.getElementById('score').textContent = `${Math.round(score * 100)}%`;
      const meter = document.getElementById('meter-fill');
      meter.style.width = `${Math.round(score * 100)}%`;
      meter.style.background = isPhishing ? 'var(--red)' : 'var(--mint)';
      const pill = document.getElementById('risk-pill');
      pill.textContent = `${String(data.risk_category).toUpperCase()} RISK`;
      pill.className = `risk-pill ${String(data.risk_category).toLowerCase()}`;
      document.getElementById('scanned-url').textContent = data.normalized_url;
      const signals = document.getElementById('explanations');
      signals.replaceChildren();
      const explanations = Array.isArray(data.explanations) ? data.explanations : [];
      if (explanations.length) {
        explanations.forEach(message => {
          const signal = document.createElement('span');
          signal.className = 'signal';
          signal.textContent = message;
          signals.appendChild(signal);
        });
      } else {
        const signal = document.createElement('span');
        signal.className = 'signal ok';
        signal.textContent = 'No common structural warning signals detected';
        signals.appendChild(signal);
      }
      showFeatures(data.features);
      document.getElementById('disclaimer').textContent = data.disclaimer || 'Predictions are estimates.';
      result.hidden = false;
      const items = safeHistory();
      items.unshift({ url: data.normalized_url, score, bad: isPhishing });
      try { localStorage.setItem('phishguard-history', JSON.stringify(items.slice(0, 8))); } catch (_) { /* History is optional. */ }
      renderHistory();
    } catch (error) {
      showError(error instanceof TypeError ? 'Could not reach the scanner. Make sure the server is running, then reload this page.' : error.message);
    } finally {
      button.disabled = false;
      button.firstElementChild.textContent = 'Scan URL';
    }
  });

  document.getElementById('clear-history').addEventListener('click', () => {
    try { localStorage.removeItem('phishguard-history'); } catch (_) { /* History is optional. */ }
    renderHistory();
  });
  renderHistory();
})();
