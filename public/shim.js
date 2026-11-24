/* Collega il gestionale al database e a Google Calendar quando gira fuori da claude.ai.
   Se claude.ai fornisce già window.claude, questo file non fa nulla. */
(function () {
  if (window.claude && window.claude.use) return;

  var cache = {};            // path -> dati
  var loaded = false;
  var colSubs = [];          // {prefix, cb}
  var docSubs = [];          // {path, cb}
  var sig = {};              // path -> firma dell'ultimo valore notificato
  var lastWrite = 0, pending = 0, timer = null, loading = null;

  function api(method, url, body) {
    return fetch(url, {
      method: method,
      credentials: 'same-origin',
      headers: body ? { 'Content-Type': 'application/json' } : {},
      body: body ? JSON.stringify(body) : undefined
    }).then(function (r) {
      if (r.status === 401 || r.status === 403) { var e = new Error('Accesso non autorizzato'); e.code = 'auth'; throw e; }
      if (!r.ok) {
        return r.json().catch(function () { return {}; }).then(function (j) { var e2 = new Error(j.error || ('Errore ' + r.status)); e2.code = 'http'; throw e2; });
      }
      return r.json();
    });
  }

  function colSnap(prefix) {
    var docs = Object.keys(cache).filter(function (p) { return p.indexOf(prefix + '/') === 0; }).map(function (p) {
      var d = cache[p];
      return { id: p.slice(prefix.length + 1), exists: true, data: function () { return JSON.parse(JSON.stringify(d)); } };
    });
    return { docs: docs, metadata: { fromCache: false } };
  }
  function docSnap(path) {
    var d = cache[path];
    return { exists: d !== undefined, data: function () { return d === undefined ? undefined : JSON.parse(JSON.stringify(d)); } };
  }

  function notify(force) {
    colSubs.forEach(function (s) {
      var k = 'col:' + s.prefix;
      var v = JSON.stringify(Object.keys(cache).filter(function (p) { return p.indexOf(s.prefix + '/') === 0; }).sort().map(function (p) { return [p, cache[p]]; }));
      if (force || sig[k + s.id] !== v) { sig[k + s.id] = v; s.cb(colSnap(s.prefix)); }
    });
    docSubs.forEach(function (s) {
      var v = JSON.stringify(cache[s.path] === undefined ? null : cache[s.path]);
      if (force || sig['doc:' + s.path + s.id] !== v) { sig['doc:' + s.path + s.id] = v; s.cb(docSnap(s.path)); }
    });
  }

  function load() {
    if (loading) return loading;
    loading = api('GET', '/api/all').then(function (r) {
      if (pending > 0 || Date.now() - lastWrite < 2500) return;   // non sovrascrivere una modifica appena fatta
      cache = r.docs || {};
      loaded = true;
      notify(false);
    }).finally(function () { loading = null; });
    return loading;
  }
  function startPolling() {
    if (timer) return;
    timer = setInterval(function () { if (!document.hidden) load().catch(function () {}); }, 6000);
    document.addEventListener('visibilitychange', function () { if (!document.hidden) load().catch(function () {}); });
  }

  var sid = 0;
  var db = {
    collection: function (prefix) {
      return {
        onSnapshot: function (cb, err) {
          var s = { prefix: prefix, cb: cb, id: ++sid };
          colSubs.push(s);
          load().then(function () { if (loaded) { sig['col:' + prefix + s.id] = undefined; notify(false); } }).catch(function (e) { if (err) err(e); });
          startPolling();
          return function () { colSubs = colSubs.filter(function (x) { return x !== s; }); };
        }
      };
    },
    doc: function (path) {
      return {
        set: function (data) {
          pending++; lastWrite = Date.now();
          cache[path] = JSON.parse(JSON.stringify(data)); notify(false);
          return api('PUT', '/api/doc?path=' + encodeURIComponent(path), data).finally(function () { pending--; lastWrite = Date.now(); });
        },
        delete: function () {
          pending++; lastWrite = Date.now();
          delete cache[path]; notify(false);
          return api('DELETE', '/api/doc?path=' + encodeURIComponent(path)).finally(function () { pending--; lastWrite = Date.now(); });
        },
        onSnapshot: function (cb, err) {
          var s = { path: path, cb: cb, id: ++sid };
          docSubs.push(s);
          load().then(function () { if (loaded) { sig['doc:' + path + s.id] = undefined; notify(false); } }).catch(function (e) { if (err) err(e); });
          startPolling();
          return function () { docSubs = docSubs.filter(function (x) { return x !== s; }); };
        }
      };
    }
  };

  var downloads = {
    save: function (o) {
      var blob = new Blob([o.data], { type: o.type || 'application/octet-stream' });
      var a = document.createElement('a');
      a.href = URL.createObjectURL(blob); a.download = o.filename || 'file';
      document.body.appendChild(a); a.click();
      setTimeout(function () { URL.revokeObjectURL(a.href); a.remove(); }, 1500);
      return Promise.resolve();
    }
  };

  var mcp = {
    callTool: function (server, tool, input) {
      if (server !== 'Google Calendar') return Promise.reject({ code: 'server_not_connected', message: 'Collegamento non disponibile' });
      return api('POST', '/api/calendar', { tool: tool, input: input }).catch(function (e) {
        if (e && e.code === 'auth') throw { code: 'needs_reauth', message: e.message };
        if (e && e.code === 'http') throw { code: 'tool_error', message: e.message };
        throw { code: 'upstream_error', message: String(e && e.message || e) };
      });
    }
  };

  window.claude = { use: function (name) {
    return Promise.resolve(name === 'db' ? db : name === 'downloads' ? downloads : name === 'mcp' ? mcp : null);
  } };
})();
