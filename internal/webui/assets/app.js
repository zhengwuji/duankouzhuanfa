/* PortTransit console front end.
 *
 * Deliberately dependency-free: the console is embedded in the binary and must
 * run on a host with no network access and no build tooling. A small hand-
 * written view layer is easier to audit than a framework, which matters for a
 * surface that can reconfigure a relay.
 *
 * Everything goes through api(), which is the single place that handles
 * authentication failure, so a session that expires mid-task always lands the
 * operator back on the login form rather than showing a silent empty table.
 */
'use strict';

const state = {
  session: null,
  view: 'dashboard',
  config: null,
  status: null,
  servers: [],
  tunnels: [],
  health: [],
  transports: [],
  logs: [],
};

/* ---------------------------------------------------------------- utilities */

const $ = (sel, root) => (root || document).querySelector(sel);

function el(tag, attrs, children) {
  const node = document.createElement(tag);
  if (attrs) {
    for (const [k, v] of Object.entries(attrs)) {
      if (v === null || v === undefined || v === false) continue;
      if (k === 'class') node.className = v;
      else if (k === 'text') node.textContent = v;
      else if (k === 'html') node.innerHTML = v;
      else if (k.startsWith('on') && typeof v === 'function') node.addEventListener(k.slice(2), v);
      else if (v === true) node.setAttribute(k, '');
      else node.setAttribute(k, v);
    }
  }
  for (const child of [].concat(children || [])) {
    if (child === null || child === undefined || child === false) continue;
    node.append(child instanceof Node ? child : document.createTextNode(String(child)));
  }
  return node;
}

function clear(node) { while (node.firstChild) node.removeChild(node.firstChild); }

/* Human-readable byte and duration rendering. A relay operator reads these
 * constantly, so they are formatted once here rather than at each call site. */
function bytes(n) {
  n = Number(n) || 0;
  const units = ['B', 'KB', 'MB', 'GB', 'TB', 'PB'];
  let i = 0;
  while (n >= 1024 && i < units.length - 1) { n /= 1024; i++; }
  return (i === 0 ? n : n.toFixed(n < 10 ? 2 : 1)) + ' ' + units[i];
}

function duration(seconds) {
  seconds = Math.floor(Number(seconds) || 0);
  const d = Math.floor(seconds / 86400);
  const h = Math.floor((seconds % 86400) / 3600);
  const m = Math.floor((seconds % 3600) / 60);
  const s = seconds % 60;
  if (d) return `${d}天 ${h}小时`;
  if (h) return `${h}小时 ${m}分`;
  if (m) return `${m}分 ${s}秒`;
  return `${s}秒`;
}

function num(n) { return (Number(n) || 0).toLocaleString('en-US'); }

function shortTime(iso) {
  if (!iso) return '—';
  const d = new Date(iso);
  if (isNaN(d)) return iso;
  return d.toLocaleTimeString('zh-CN', { hour12: false });
}

function toast(message, kind) {
  const box = $('#toasts');
  const node = el('div', { class: 'toast ' + (kind || ''), text: message });
  box.append(node);
  setTimeout(() => node.remove(), kind === 'bad' ? 7000 : 4200);
}

/* ---------------------------------------------------------------------- api */

async function api(path, options) {
  const opts = Object.assign({ headers: {} }, options || {});
  if (opts.body !== undefined && typeof opts.body !== 'string') {
    opts.body = JSON.stringify(opts.body);
    opts.headers['Content-Type'] = 'application/json';
  }
  const resp = await fetch(path, opts);
  let data = null;
  const text = await resp.text();
  if (text) {
    try { data = JSON.parse(text); } catch (_) { data = { raw: text }; }
  }
  if (resp.status === 401) {
    showLogin();
    throw new Error('登录已过期，请重新登录');
  }
  if (!resp.ok) {
    const detail = data && (data.errors ? data.errors.join('；') : data.error) || resp.statusText;
    const err = new Error(detail);
    err.status = resp.status;
    err.data = data;
    throw err;
  }
  return data;
}

/* -------------------------------------------------------------------- modal */

function openModal(title, content) {
  $('#modal-title').textContent = title;
  const body = $('#modal-content');
  clear(body);
  body.append(content);
  $('#modal').hidden = false;
}

function closeModal() { $('#modal').hidden = true; }

/* ------------------------------------------------------------------- views */

const VIEWS = {
  dashboard: { title: '总览', render: renderDashboard },
  servers: { title: '中转服务器', render: renderServers },
  tunnels: { title: '端口转发', render: renderTunnels },
  health: { title: '线路健康', render: renderHealth },
  deploy: { title: '远程部署', render: renderDeploy },
  logs: { title: '日志', render: renderLogs },
  settings: { title: '设置', render: renderSettings },
};

async function show(viewName) {
  state.view = viewName;
  const view = VIEWS[viewName];
  $('#view-title').textContent = view.title;
  for (const btn of document.querySelectorAll('.nav-item')) {
    btn.classList.toggle('active', btn.dataset.view === viewName);
  }
  const host = $('#view');
  clear(host);
  host.append(el('div', { class: 'empty', text: '正在加载…' }));
  try {
    await view.render(host);
  } catch (err) {
    clear(host);
    host.append(el('div', { class: 'notice bad', text: err.message }));
  }
}

async function refreshCurrent() { await show(state.view); }

/* --------------------------------------------------------------- dashboard */

async function renderDashboard(host) {
  const status = await api('/api/v1/status');
  state.status = status;
  clear(host);

  const version = status.version || {};
  const cards = el('div', { class: 'grid cols-4' });

  const server = status.server;
  if (server && server.stats) {
    const s = server.stats;
    cards.append(
      stat('活动连接', num(s.activeConnections), '个'),
      stat('累计连接', num(s.totalConnections), '个'),
      stat('上行流量', bytes(s.bytesUp)),
      stat('下行流量', bytes(s.bytesDown)),
    );
  }
  const client = status.client;
  if (client && client.stats) {
    const c = client.stats;
    cards.append(
      stat('活动连接', num(c.activeConnections), '个'),
      stat('隧道失败', num(c.tunnelFailures), '次'),
      stat('上行流量', bytes(c.bytesUp)),
      stat('下行流量', bytes(c.bytesDown)),
    );
  }
  host.append(cards);

  const info = el('div', { class: 'card' }, [
    el('h2', { text: '运行状态' }),
    el('div', { class: 'grid cols-3' }, [
      stat('运行模式', status.mode || '—'),
      stat('运行时长', duration(status.uptime)),
      stat('控制台', status.webui ? status.webui.url : '—'),
      stat('版本', version.version || '—'),
      stat('协议版本', 'v' + (version.protocol || '—')),
      stat('活动会话', num(status.sessions)),
    ]),
  ]);
  host.append(info);

  if (server) {
    host.append(relayPanel(server));
  }
  if (client) {
    host.append(clientPanel(client));
  }
}

function stat(label, value, unit) {
  const valueNode = el('div', { class: 'value' }, [
    String(value),
    unit ? el('span', { class: 'unit', text: unit }) : null,
  ]);
  return el('div', { class: 'stat' }, [
    el('div', { class: 'label', text: label }),
    valueNode,
  ]);
}

function relayPanel(server) {
  const s = server.stats || {};
  const rows = (server.listeners || []).map((l) => {
    // The state column reports whether the port is actually bound, not merely
    // whether it is configured. A listener that is enabled but failed to bind
    // is the single most confusing state for an operator: the config says the
    // port should be open and clients still cannot connect.
    let state;
    if (l.listening) {
      state = el('span', { class: 'badge ok', text: '监听中' });
    } else if (!l.enabled) {
      state = el('span', { class: 'badge mute', text: '已停用' });
    } else {
      state = el('span', { class: 'badge bad', text: '未监听' });
    }
    const stateCell = l.reason
      ? el('td', {}, [state, el('div', { class: 'muted small', text: l.reason })])
      : el('td', {}, [state]);

    return el('tr', {}, [
      el('td', { text: l.name }),
      el('td', {}, [el('span', { class: 'badge info', text: l.transport })]),
      el('td', { class: 'mono', text: l.listen }),
      stateCell,
      el('td', { text: num(l.active) }),
      el('td', { text: num(l.accepted) }),
      el('td', { text: num(l.rejected) }),
    ]);
  });

  const table = rows.length
    ? el('div', { class: 'table-wrap' }, [
        el('table', {}, [
          el('thead', {}, [el('tr', {}, [
            el('th', { text: '名称' }), el('th', { text: '协议' }), el('th', { text: '监听地址' }),
            el('th', { text: '状态' }), el('th', { text: '活动' }), el('th', { text: '已接受' }), el('th', { text: '已拒绝' }),
          ])]),
          el('tbody', {}, rows),
        ]),
      ])
    : el('div', { class: 'empty', text: '本机未配置中转监听端口' });

  return el('div', { class: 'card' }, [
    el('h2', { text: '中转服务端' }),
    el('p', { class: 'muted', text: '本机作为中转节点对外提供的加密转发入口。' }),
    table,
    el('div', { class: 'grid cols-4' }, [
      stat('握手失败', num(s.handshakeFailures), '次'),
      stat('限流丢弃', num(s.rejectedThrottled), '次'),
      stat('ACL 拒绝', num(s.aclDenied), '次'),
      stat('平均拨号', (Number(s.avgDialMs) || 0).toFixed(1), 'ms'),
    ]),
  ]);
}

function clientPanel(client) {
  const proxy = client.proxy || {};
  const tunnelRows = (client.tunnels || []).map((t) =>
    el('tr', {}, [
      el('td', { text: t.name }),
      el('td', { class: 'mono', text: t.listen }),
      el('td', { class: 'mono', text: t.target }),
      el('td', {}, [t.enabled ? el('span', { class: 'badge ok', text: '已启用' }) : el('span', { class: 'badge mute', text: '已停用' })]),
      el('td', { text: num(t.active) }),
      el('td', { text: num(t.accepted) }),
      el('td', {}, [Number(t.failed) > 0 ? el('span', { class: 'badge warn', text: num(t.failed) }) : el('td', { text: '0' })]),
    ])
  );

  const endpoints = el('div', { class: 'grid cols-3' }, [
    stat('SOCKS5', proxy.socks5 || '未启用'),
    stat('HTTP', proxy.http || '未启用'),
    stat('代理请求', num((client.stats || {}).proxyRequests), '次'),
  ]);

  return el('div', { class: 'card' }, [
    el('h2', { text: '客户端' }),
    el('p', { class: 'muted', text: '本机作为客户端，通过中转服务器转发本地流量。' }),
    endpoints,
    tunnelRows.length
      ? el('div', { class: 'table-wrap' }, [
          el('table', {}, [
            el('thead', {}, [el('tr', {}, [
              el('th', { text: '名称' }), el('th', { text: '本地监听' }), el('th', { text: '目标地址' }),
              el('th', { text: '状态' }), el('th', { text: '活动' }), el('th', { text: '已接受' }), el('th', { text: '失败' }),
            ])]),
            el('tbody', {}, tunnelRows),
          ]),
        ])
      : el('div', { class: 'empty', text: '尚未配置端口转发规则' }),
  ]);
}

/* ----------------------------------------------------------------- servers */

async function renderServers(host) {
  const data = await api('/api/v1/servers');
  state.servers = data.servers || [];
  clear(host);

  const addBtn = el('button', { class: 'btn primary', text: '+ 添加中转服务器', onclick: () => serverForm(null) });

  host.append(el('div', { class: 'card' }, [
    el('div', { class: 'row' }, [
      el('h2', { text: '中转服务器列表' }),
      el('div', { class: 'spacer' }),
      addBtn,
    ]),
    el('p', { class: 'muted', text: '客户端通过这些服务器转发流量。可以按分组配置多条线路，实现故障自动切换。' }),
  ]));

  if (!state.servers.length) {
    host.append(el('div', { class: 'card' }, [
      el('div', { class: 'empty', text: '还没有添加中转服务器。点击右上角按钮添加，或使用「远程部署」在服务器上一键安装。' }),
    ]));
    return;
  }

  const rows = state.servers.map((s) => el('tr', {}, [
    el('td', {}, [
      el('div', { text: s.name || s.id }),
      el('div', { class: 'muted mono', text: s.id }),
    ]),
    el('td', { class: 'mono', text: s.address }),
    el('td', {}, [el('span', { class: 'badge info', text: s.transport })]),
    el('td', { text: s.group || '—' }),
    el('td', { text: s.latencyTag || '—' }),
    el('td', {}, [s.enabled ? el('span', { class: 'badge ok', text: '已启用' }) : el('span', { class: 'badge mute', text: '已停用' })]),
    el('td', { class: 'nowrap' }, [
      el('button', { class: 'btn small ghost', text: '编辑', onclick: () => serverForm(s) }),
      ' ',
      el('button', { class: 'btn small ghost', text: '测试', onclick: (e) => probeServer(s.id, e.target) }),
      ' ',
      el('button', { class: 'btn small danger', text: '删除', onclick: () => deleteServer(s) }),
    ]),
  ]));

  host.append(el('div', { class: 'card' }, [
    el('div', { class: 'table-wrap' }, [
      el('table', {}, [
        el('thead', {}, [el('tr', {}, [
          el('th', { text: '名称' }), el('th', { text: '地址' }), el('th', { text: '协议' }),
          el('th', { text: '分组' }), el('th', { text: '线路标记' }), el('th', { text: '状态' }), el('th', { text: '操作' }),
        ])]),
        el('tbody', {}, rows),
      ]),
    ]),
  ]));
}

function serverForm(existing) {
  const s = existing || { enabled: true, transport: 'tls', group: '', weight: 1 };
  const form = el('form', { class: 'modal-form' });

  const nameIn = input('名称', s.name || '', 'text', '例如：上海中转');
  const addrIn = input('服务器地址', s.address || '', 'text', '例如：relay.example.com:443');
  const transportSel = select('协议', state.transports.length
    ? state.transports.map((t) => ({ value: t.name, label: t.name + (t.encrypted ? '（加密）' : '（明文）') }))
    : [{ value: 'tls', label: 'tls' }], s.transport);
  const groupIn = input('分组', s.group || '', 'text', '同组服务器之间可自动切换');
  const tagIn = input('线路标记', s.latencyTag || '', 'text', '例如：日本→上海→美国');
  const idIn = input('客户端 ID', s.clientId || '', 'text', '服务端按客户端 ID 下发权限，可留空');
  const enabledIn = checkbox('启用该服务器', s.enabled !== false);
  // The transport settings are free-form JSON because each protocol needs
  // different keys. The hint lists the ones that are easy to get wrong, and it
  // names certFingerprint explicitly: the point of pinning is that an operator
  // reaches for it instead of insecure, and one who does not know the key
  // exists cannot reach for it.
  const settingsIn = textarea(
    '协议参数 (JSON) — tls 可用 fingerprint: chrome/firefox/safari/edge/ios/android/golang/random/random-no-alpn；'
    + '自签证书建议用 certFingerprint（SHA-256 指纹，可用 porttransit fingerprint 获取）代替 insecure；'
    + 'mux: true 可开启多路复用（服务端 listener 也要开，且仅 direct/tls/ws/httpupgrade/reality 支持）',
    JSON.stringify(s.settings || {}, null, 2),
  );

  form.append(
    field(nameIn), field(addrIn), field(transportSel), field(groupIn),
    field(tagIn), field(idIn), field(settingsIn), field(enabledIn),
    el('div', { class: 'row end' }, [
      el('button', { class: 'btn ghost', type: 'button', text: '取消', onclick: closeModal }),
      el('button', { class: 'btn primary', type: 'submit', text: '保存' }),
    ]),
  );

  form.addEventListener('submit', async (ev) => {
    ev.preventDefault();
    let settings;
    try {
      settings = JSON.parse(settingsIn.querySelector('textarea').value || '{}');
    } catch (err) {
      toast('协议参数不是合法的 JSON：' + err.message, 'bad');
      return;
    }
    const payload = {
      id: s.id || '',
      name: nameIn.querySelector('input').value.trim(),
      address: addrIn.querySelector('input').value.trim(),
      transport: transportSel.querySelector('select').value,
      group: groupIn.querySelector('input').value.trim(),
      latencyTag: tagIn.querySelector('input').value.trim(),
      clientId: idIn.querySelector('input').value.trim(),
      enabled: enabledIn.querySelector('input').checked,
      settings,
    };
    try {
      if (s.id) {
        await api('/api/v1/servers/' + encodeURIComponent(s.id), { method: 'PUT', body: payload });
        toast('已更新中转服务器', 'ok');
      } else {
        await api('/api/v1/servers', { method: 'POST', body: payload });
        toast('已添加中转服务器', 'ok');
      }
      closeModal();
      await refreshCurrent();
    } catch (err) {
      toast(err.message, 'bad');
    }
  });

  openModal(existing ? '编辑中转服务器' : '添加中转服务器', form);
}

async function deleteServer(s) {
  if (!confirm(`确定删除中转服务器「${s.name || s.id}」？`)) return;
  try {
    await api('/api/v1/servers/' + encodeURIComponent(s.id), { method: 'DELETE' });
    toast('已删除', 'ok');
    await refreshCurrent();
  } catch (err) {
    toast(err.message, 'bad');
  }
}

async function probeServer(id, button) {
  const original = button.textContent;
  button.disabled = true;
  button.textContent = '测试中…';
  try {
    const data = await api('/api/v1/probe', { method: 'POST', body: { serverId: id } });
    const s = data.server || {};
    if (s.healthy) {
      toast(`连通，延迟 ${s.latencyMs || 0} ms`, 'ok');
    } else {
      toast(`不通：${s.lastError || '未知错误'}`, 'bad');
    }
  } catch (err) {
    toast(err.message, 'bad');
  } finally {
    button.disabled = false;
    button.textContent = original;
  }
}

/* ----------------------------------------------------------------- tunnels */

async function renderTunnels(host) {
  const data = await api('/api/v1/tunnels');
  state.tunnels = data.tunnels || [];
  const statusByName = {};
  for (const st of data.status || []) statusByName[st.name] = st;

  clear(host);
  host.append(el('div', { class: 'card' }, [
    el('div', { class: 'row' }, [
      el('h2', { text: '端口转发规则' }),
      el('div', { class: 'spacer' }),
      el('button', { class: 'btn primary', text: '+ 新建转发', onclick: () => tunnelForm(null) }),
    ]),
    el('p', { class: 'muted', text: '把本地端口固定转发到某个目标地址，流量经由中转服务器出去。适合给游戏、SSH、数据库等固定目标加速。' }),
    el('div', { class: 'notice', text: '新增或修改本地监听端口后，需要重启客户端服务才会生效。' }),
  ]));

  if (!state.tunnels.length) {
    host.append(el('div', { class: 'card' }, [
      el('div', { class: 'empty', text: '还没有转发规则。' }),
    ]));
    return;
  }

  const rows = state.tunnels.map((t) => {
    const st = statusByName[t.name] || {};
    return el('tr', {}, [
      el('td', { text: t.name }),
      el('td', { class: 'mono', text: t.listen }),
      el('td', { class: 'mono', text: t.target }),
      el('td', { text: t.server || (t.group ? '分组 ' + t.group : '自动选择') }),
      el('td', {}, [t.enabled ? el('span', { class: 'badge ok', text: '已启用' }) : el('span', { class: 'badge mute', text: '已停用' })]),
      el('td', { text: num(st.active) }),
      el('td', { text: num(st.accepted) }),
      el('td', {}, [Number(st.failed) > 0 ? el('span', { class: 'badge bad', text: num(st.failed) }) : el('span', { class: 'muted', text: '0' })]),
      el('td', { class: 'nowrap' }, [
        el('button', { class: 'btn small ghost', text: '编辑', onclick: () => tunnelForm(t) }),
        ' ',
        el('button', { class: 'btn small danger', text: '删除', onclick: () => deleteTunnel(t) }),
      ]),
    ]);
  });

  host.append(el('div', { class: 'card' }, [
    el('div', { class: 'table-wrap' }, [
      el('table', {}, [
        el('thead', {}, [el('tr', {}, [
          el('th', { text: '名称' }), el('th', { text: '本地监听' }), el('th', { text: '目标' }),
          el('th', { text: '经由' }), el('th', { text: '状态' }), el('th', { text: '活动' }),
          el('th', { text: '已接受' }), el('th', { text: '失败' }), el('th', { text: '操作' }),
        ])]),
        el('tbody', {}, rows),
      ]),
    ]),
  ]));
}

function tunnelForm(existing) {
  const t = existing || { enabled: true, network: 'tcp', balance: 'first' };
  const form = el('form');

  const nameIn = input('名称', t.name || '', 'text', '例如：日本游戏加速');
  const listenIn = input('本地监听地址', t.listen || '127.0.0.1:', 'text', '例如：127.0.0.1:8080');
  const targetIn = input('目标地址', t.target || '', 'text', '例如：jp.example.com:443');
  const serverSel = select('指定服务器', [{ value: '', label: '（不指定，按分组或自动选择）' }]
    .concat(state.servers.map((s) => ({ value: s.id, label: (s.name || s.id) + ' — ' + s.address }))), t.server || '');
  const groupIn = input('分组', t.group || '', 'text', '留空则使用全部可用服务器');
  const networkSel = select('传输类型', [
    { value: 'tcp', label: 'TCP' },
    { value: 'udp', label: 'UDP' },
  ], t.network || 'tcp');
  const balanceSel = select('负载策略', [
    { value: 'first', label: '优先第一个' },
    { value: 'round-robin', label: '轮询' },
    { value: 'random', label: '随机' },
    { value: 'least-latency', label: '延迟最低' },
  ], t.balance || 'first');
  const enabledIn = checkbox('启用该转发', t.enabled !== false);

  form.append(
    field(nameIn), field(listenIn), field(targetIn), field(serverSel),
    field(groupIn), field(networkSel), field(balanceSel), field(enabledIn),
    el('div', { class: 'row end' }, [
      el('button', { class: 'btn ghost', type: 'button', text: '取消', onclick: closeModal }),
      el('button', { class: 'btn primary', type: 'submit', text: '保存' }),
    ]),
  );

  form.addEventListener('submit', async (ev) => {
    ev.preventDefault();
    const payload = {
      name: nameIn.querySelector('input').value.trim(),
      listen: listenIn.querySelector('input').value.trim(),
      target: targetIn.querySelector('input').value.trim(),
      server: serverSel.querySelector('select').value,
      group: groupIn.querySelector('input').value.trim(),
      balance: balanceSel.querySelector('select').value,
      network: networkSel.querySelector('select').value,
      enabled: enabledIn.querySelector('input').checked,
    };
    try {
      if (t.name) {
        await api('/api/v1/tunnels/' + encodeURIComponent(t.name), { method: 'PUT', body: payload });
      } else {
        await api('/api/v1/tunnels', { method: 'POST', body: payload });
      }
      toast('已保存，重启客户端后生效', 'ok');
      closeModal();
      await refreshCurrent();
    } catch (err) {
      toast(err.message, 'bad');
    }
  });

  openModal(existing ? '编辑端口转发' : '新建端口转发', form);
}

async function deleteTunnel(t) {
  if (!confirm(`确定删除转发规则「${t.name}」？`)) return;
  try {
    await api('/api/v1/tunnels/' + encodeURIComponent(t.name), { method: 'DELETE' });
    toast('已删除', 'ok');
    await refreshCurrent();
  } catch (err) {
    toast(err.message, 'bad');
  }
}

/* ------------------------------------------------------------------ health */

async function renderHealth(host) {
  const data = await api('/api/v1/health');
  state.health = data.servers || [];
  // The probe counters live in the client stats, not in the per-server health
  // rows, so they are fetched separately. They are the only evidence that the
  // periodic checker is actually running: without them an operator staring at
  // "last check" times cannot tell a scheduled probe from a manual one.
  let stats = {};
  try {
    const status = await api('/api/v1/status');
    stats = ((status.client || {}).stats) || {};
  } catch (err) {
    stats = {};
  }
  clear(host);

  if (!state.health.length) {
    host.append(el('div', { class: 'card' }, [el('div', { class: 'empty', text: '没有可检测的中转服务器。' })]));
    return;
  }

  const rows = state.health.map((s) => {
    const badge = s.healthy
      ? el('span', { class: 'badge ok', text: '正常' })
      : el('span', { class: 'badge bad', text: '不可用' });
    const latency = s.latencyOk ? `${s.latencyMs} ms` : '未测量';
    return el('tr', {}, [
      el('td', { text: s.name || s.id }),
      el('td', { class: 'mono', text: s.address }),
      el('td', {}, [el('span', { class: 'badge info', text: s.transport })]),
      el('td', { text: s.group || '—' }),
      el('td', { text: s.latencyTag || '—' }),
      el('td', {}, [badge]),
      el('td', { class: 'mono', text: latency }),
      el('td', { class: 'mono', text: shortTime(s.lastCheck) }),
      el('td', {}, [Number(s.consecutiveFailures) > 0 ? el('span', { class: 'badge warn', text: num(s.consecutiveFailures) }) : el('span', { class: 'muted', text: '0' })]),
      el('td', { class: 'muted', text: s.lastError || '—' }),
      el('td', {}, [el('button', { class: 'btn small ghost', text: '立即测试', onclick: (e) => probeServer(s.id, e.target) })]),
    ]);
  });

  host.append(el('div', { class: 'card' }, [
    el('h2', { text: '线路健康' }),
    el('p', { class: 'muted', text: '客户端会周期性探测每条中转线路。连续失败达到阈值后自动切换，恢复后自动切回。' }),
    el('div', { class: 'table-wrap' }, [
      el('table', {}, [
        el('thead', {}, [el('tr', {}, [
          el('th', { text: '名称' }), el('th', { text: '地址' }), el('th', { text: '协议' }),
          el('th', { text: '分组' }), el('th', { text: '线路' }), el('th', { text: '状态' }),
          el('th', { text: '延迟' }), el('th', { text: '最近检测' }), el('th', { text: '连续失败' }),
          el('th', { text: '最近错误' }), el('th', { text: '操作' }),
        ])]),
        el('tbody', {}, rows),
      ]),
    ]),
    el('div', { class: 'grid cols-3' }, [
      stat('累计探测', num(stats.healthChecks), '次'),
      stat('探测失败', num(stats.healthFailures), '次'),
      stat('线路总数', num(state.health.length), '条'),
    ]),
  ]));
}

/* ------------------------------------------------------------------ deploy */

async function renderDeploy(host) {
  clear(host);
  host.append(el('div', { class: 'card' }, [
    el('h2', { text: '远程部署中转服务端' }),
    el('p', { class: 'muted', text: '通过 SSH 连接到一台 Debian / Ubuntu 服务器，自动安装并配置 PortTransit 服务端。' }),
    el('div', { class: 'notice warn', text: '请使用 root 账号或具备 sudo 权限的账号，并确认已配置好 SSH 密钥或密码。' }),
  ]));

  const form = el('form', { class: 'card' });
  const hostIn = input('服务器地址', '', 'text', '例如：1.2.3.4 或 relay.example.com');
  const portIn = input('SSH 端口', '22', 'number');
  const userIn = input('SSH 用户名', 'root', 'text');
  const authSel = select('认证方式', [
    { value: 'key', label: 'SSH 私钥' },
    { value: 'password', label: '密码' },
  ], 'key');
  const keyIn = input('SSH 私钥路径', '', 'text', '例如：C:\\Users\\me\\.ssh\\id_rsa（留空使用默认密钥）');
  const passIn = input('SSH 密码', '', 'password', '仅在密码认证时需要');
  const transportSel = select('中转协议', state.transports.length
    ? state.transports.filter((t) => t.encrypted).map((t) => ({ value: t.name, label: t.name }))
    : [{ value: 'tls', label: 'tls' }], 'tls');
  const relayPortIn = input('中转监听端口', '8443', 'number', '建议使用 443 或 8443');
  const nameIn = input('线路名称', '', 'text', '例如：上海中转（留空自动命名）');
  // Only used when this console runs on a platform the relay cannot use —
  // most often a Windows console deploying to a Linux server. Deploy uploads
  // its own binary first and falls back to this URL.
  const dlIn = input('服务端下载地址（可选）', '', 'text',
    '留空则上传本机程序；本机程序不能在服务器上运行时才会用到，支持 {os}/{arch}');

  form.append(
    field(hostIn), field(portIn), field(userIn), field(authSel),
    field(keyIn), field(passIn), field(transportSel), field(relayPortIn), field(nameIn),
    field(dlIn),
    el('div', { class: 'row end' }, [
      el('button', { class: 'btn primary', type: 'submit', text: '开始部署' }),
    ]),
  );

  const output = el('pre', { class: 'log-view', hidden: true });
  const card = el('div', { class: 'card' }, [el('h2', { text: '部署输出' }), output]);

  form.addEventListener('submit', async (ev) => {
    ev.preventDefault();
    const payload = {
      host: hostIn.querySelector('input').value.trim(),
      port: Number(portIn.querySelector('input').value) || 22,
      username: userIn.querySelector('input').value.trim(),
      authMethod: authSel.querySelector('select').value,
      privateKeyPath: keyIn.querySelector('input').value.trim(),
      password: passIn.querySelector('input').value,
      transport: transportSel.querySelector('select').value,
      relayPort: Number(relayPortIn.querySelector('input').value) || 8443,
      name: nameIn.querySelector('input').value.trim(),
      downloadUrl: dlIn.querySelector('input').value.trim(),
    };
    if (!payload.host) { toast('请填写服务器地址', 'bad'); return; }

    output.hidden = false;
    clear(output);
    output.append(el('div', { text: '正在连接 ' + payload.host + ' …' }));
    try {
      const result = await api('/api/v1/deploy', { method: 'POST', body: payload });
      clear(output);
      for (const line of result.log || []) output.append(el('div', { text: line }));
      if (result.ok) {
        output.append(el('div', { class: 'success', text: '✔ 部署完成：' + (result.summary || '') }));
        toast('部署完成', 'ok');
      } else {
        output.append(el('div', { class: 'error', text: '✘ 部署失败：' + (result.error || '未知错误') }));
        toast('部署失败：' + (result.error || ''), 'bad');
      }
    } catch (err) {
      clear(output);
      output.append(el('div', { class: 'error', text: '✘ ' + err.message }));
      toast(err.message, 'bad');
    }
  });

  host.append(form);
  host.append(card);
}

/* -------------------------------------------------------------------- logs */

async function renderLogs(host) {
  const level = state.logLevel || 'info';
  const data = await api('/api/v1/logs?limit=400&level=' + encodeURIComponent(level));
  state.logs = data.entries || [];
  clear(host);

  const select_ = select('最低级别', [
    { value: 'debug', label: 'debug' },
    { value: 'info', label: 'info' },
    { value: 'warn', label: 'warn' },
    { value: 'error', label: 'error' },
  ], level);
  select_.querySelector('select').addEventListener('change', (e) => {
    state.logLevel = e.target.value;
    refreshCurrent();
  });

  const box = el('div', { class: 'log-view' });
  if (!state.logs.length) {
    box.append(el('div', { class: 'empty', text: '暂无日志。' }));
  } else {
    for (const entry of state.logs) {
      const lvl = String(entry.Level || entry.level || 'info').toLowerCase();
      box.append(el('div', { class: 'log-line level-' + lvl }, [
        el('span', { class: 't', text: shortTime(entry.Time || entry.time) }),
        el('span', { class: 'l', text: lvl.toUpperCase() }),
        el('span', { class: 'm', text: formatLogMessage(entry) }),
      ]));
    }
  }

  host.append(el('div', { class: 'card' }, [
    el('div', { class: 'row' }, [
      el('h2', { text: '运行日志' }),
      el('div', { class: 'spacer' }),
      el('div', { style: 'width:160px' }, [select_]),
    ]),
    box,
  ]));
}

function formatLogMessage(entry) {
  const msg = entry.Message || entry.message || '';
  const attrs = entry.Attrs || entry.attrs || {};
  const parts = Object.entries(attrs).map(([k, v]) => `${k}=${v}`);
  return parts.length ? `${msg}  ${parts.join(' ')}` : msg;
}

/* ---------------------------------------------------------------- settings */

async function renderSettings(host) {
  const data = await api('/api/v1/config');
  state.config = data.config;
  clear(host);

  host.append(el('div', { class: 'card' }, [
    el('h2', { text: '配置文件' }),
    el('p', { class: 'muted' }, ['路径：', el('span', { class: 'mono', text: data.path })]),
  ]));

  // Password change.
  const pwForm = el('form', { class: 'card' });
  const userIn = input('管理员用户名', (state.config.webui || {}).username || 'admin', 'text');
  const curIn = input('当前密码', '', 'password');
  const newIn = input('新密码', '', 'password', '至少 8 位');
  const newIn2 = input('确认新密码', '', 'password');
  pwForm.append(
    el('h2', { text: '修改管理员账号密码' }),
    el('p', { class: 'muted', text: '修改后所有登录会话都会失效，需要用新密码重新登录。' }),
    field(userIn), field(curIn), field(newIn), field(newIn2),
    el('div', { class: 'row end' }, [el('button', { class: 'btn primary', type: 'submit', text: '保存' })]),
  );
  pwForm.addEventListener('submit', async (ev) => {
    ev.preventDefault();
    const np = newIn.querySelector('input').value;
    if (np !== newIn2.querySelector('input').value) { toast('两次输入的新密码不一致', 'bad'); return; }
    try {
      await api('/api/v1/password', {
        method: 'POST',
        body: {
          username: userIn.querySelector('input').value.trim(),
          current: curIn.querySelector('input').value,
          password: np,
        },
      });
      toast('密码已修改，请重新登录', 'ok');
      setTimeout(showLogin, 800);
    } catch (err) {
      toast(err.message, 'bad');
    }
  });
  host.append(pwForm);

  // Raw configuration editor.
  const rawForm = el('form', { class: 'card' });
  const editor = el('textarea', { rows: '22' });
  editor.value = JSON.stringify(state.config, null, 2);
  rawForm.append(
    el('h2', { text: '高级：直接编辑配置' }),
    el('p', { class: 'muted', text: '密钥类字段显示为 __redacted__，保持原样即可，不会覆盖已保存的密钥。' }),
    editor,
    el('div', { class: 'row end' }, [
      el('button', { class: 'btn ghost', type: 'button', text: '校验', onclick: async () => {
        try {
          const parsed = JSON.parse(editor.value);
          const res = await api('/api/v1/config/validate', { method: 'POST', body: { config: parsed } });
          if (res.valid) toast('配置校验通过', 'ok');
          else toast('配置有问题：' + (res.errors || []).join('；'), 'bad');
        } catch (err) { toast(err.message, 'bad'); }
      }}),
      el('button', { class: 'btn ghost', type: 'button', text: '重新载入', onclick: refreshCurrent }),
      el('button', { class: 'btn primary', type: 'submit', text: '保存并校验' }),
    ]),
  );
  rawForm.addEventListener('submit', async (ev) => {
    ev.preventDefault();
    let parsed;
    try { parsed = JSON.parse(editor.value); } catch (err) { toast('JSON 解析失败：' + err.message, 'bad'); return; }
    try {
      const res = await api('/api/v1/config/validate', { method: 'POST', body: { config: parsed } });
      if (!res.valid) { toast('配置未通过校验：' + (res.errors || []).join('；'), 'bad'); return; }
      toast('配置校验通过。请通过 SSH 或服务管理命令写入并重启服务。', 'ok');
    } catch (err) {
      toast(err.message, 'bad');
    }
  });
  host.append(rawForm);

  // Available transports.
  const list = el('div', { class: 'table-wrap' }, [
    el('table', {}, [
      el('thead', {}, [el('tr', {}, [
        el('th', { text: '协议' }), el('th', { text: '加密' }), el('th', { text: '默认端口' }), el('th', { text: '说明' }),
      ])]),
      el('tbody', {}, state.transports.map((t) => el('tr', {}, [
        el('td', { class: 'mono', text: t.name }),
        el('td', {}, [t.encrypted ? el('span', { class: 'badge ok', text: '加密' }) : el('span', { class: 'badge warn', text: '明文' })]),
        el('td', { class: 'mono', text: String(t.defaultPort) }),
        el('td', { class: 'muted', text: t.description }),
      ]))),
    ]),
  ]);
  host.append(el('div', { class: 'card' }, [el('h2', { text: '可用转发协议' }), list]));
}

/* ------------------------------------------------------------- form helpers */

function field(node) { return node; }

function input(label, value, type, placeholder) {
  const id = 'f-' + Math.random().toString(36).slice(2, 9);
  return el('label', { for: id }, [
    label,
    el('input', { id, type: type || 'text', value: value || '', placeholder: placeholder || '' }),
  ]);
}

function checkbox(label, checked) {
  const id = 'f-' + Math.random().toString(36).slice(2, 9);
  return el('label', { class: 'check', for: id }, [
    el('input', { id, type: 'checkbox', checked: checked ? true : null }),
    label,
  ]);
}

function select(label, options, value) {
  const id = 'f-' + Math.random().toString(36).slice(2, 9);
  const sel = el('select', { id });
  for (const opt of options) {
    sel.append(el('option', { value: opt.value, text: opt.label, selected: String(opt.value) === String(value) ? true : null }));
  }
  return el('label', { for: id }, [label, sel]);
}

function textarea(label, value) {
  const id = 'f-' + Math.random().toString(36).slice(2, 9);
  const ta = el('textarea', { id, rows: '7', spellcheck: 'false' });
  ta.value = value || '';
  return el('label', { for: id }, [label, ta]);
}

/* -------------------------------------------------------------- auth flow */

function showLogin() {
  $('#app').hidden = true;
  $('#login').hidden = false;
  const pass = $('#login-pass');
  if (pass) pass.value = '';
}

async function showApp(session) {
  state.session = session;
  $('#login').hidden = true;
  $('#app').hidden = false;
  $('#brand-version').textContent = 'v' + ((session.version || {}).version || '?');
  $('#mode-badge').textContent = session.mode || '';

  if (!state.transports.length) {
    try {
      const data = await api('/api/v1/transports');
      state.transports = data.transports || [];
    } catch (_) { /* the protocol list is cosmetic; a failure must not block the console */ }
  }
  await show(state.view);
}

async function bootstrap() {
  try {
    const session = await api('/api/v1/session');
    if (session.authenticated) {
      await showApp(session);
    } else {
      showLogin();
    }
  } catch (_) {
    showLogin();
  }
}

/* -------------------------------------------------------------- event wiring */

$('#login-form').addEventListener('submit', async (ev) => {
  ev.preventDefault();
  const errBox = $('#login-error');
  errBox.hidden = true;
  try {
    await api('/api/v1/login', {
      method: 'POST',
      body: { username: $('#login-user').value, password: $('#login-pass').value },
    });
    await bootstrap();
  } catch (err) {
    errBox.textContent = err.message;
    errBox.hidden = false;
  }
});

$('#logout').addEventListener('click', async () => {
  try { await api('/api/v1/logout', { method: 'POST' }); } catch (_) { /* ignore */ }
  showLogin();
});

$('#refresh').addEventListener('click', () => refreshCurrent());

for (const btn of document.querySelectorAll('.nav-item')) {
  btn.addEventListener('click', () => show(btn.dataset.view));
}

$('#modal').addEventListener('click', (ev) => {
  if (ev.target.dataset && ev.target.dataset.close) closeModal();
});

document.addEventListener('keydown', (ev) => {
  if (ev.key === 'Escape') closeModal();
});

bootstrap();
