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

// True while the login form's own request is in flight.
//
// api() answers a 401 by showing the login form, which clears the password
// field. That is right for an expired session on an authenticated call, and
// wrong for a rejected login: it wiped the password the operator had just
// typed, so a mistyped character looked like the console refusing to accept
// anything at all. The handler that is already on the login form owns that
// case and reports the server's message itself.
let waitingOnLogin = false;

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
    // A 401 does not always mean an expired session: it is also what the login
    // endpoint returns for a wrong password. Reporting every one of them as
    // "登录已过期，请重新登录" told an operator who had simply mistyped their
    // password that their session had expired — and, on the login form itself,
    // it sent them looking for a session problem that did not exist.
    //
    // The server's own message is preferred whenever it sent one; the generic
    // wording is only the fallback for a bare 401 from an authenticated call.
    const serverMessage = data && (data.errors ? data.errors.join('；') : data.error);
    if (!waitingOnLogin) showLogin();
    throw new Error(serverMessage || '登录已过期，请重新登录');
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
  guide: { title: '使用说明', render: renderGuide },
  servers: { title: '中转服务器', render: renderServers },
  tunnels: { title: '端口转发', render: renderTunnels },
  health: { title: '线路健康', render: renderHealth },
  deploy: { title: '远程部署', render: renderDeploy },
  logs: { title: '日志', render: renderLogs },
  settings: { title: '设置', render: renderSettings },
};

async function show(viewName) {
  state.view = viewName;
  stopHostRefresh();
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

/* ---------------------------------------------------------- host refresh */

// The overview is the one view that polls: the relay's counters are already
// live through the relay itself, but CPU and memory are only interesting when
// they are current, and a page that silently freezes while an operator watches
// a spike is worse than one that never claimed to be live.
let hostTimer = null;

function stopHostRefresh() {
  if (hostTimer !== null) {
    clearInterval(hostTimer);
    hostTimer = null;
  }
}

function startHostRefresh(seconds) {
  stopHostRefresh();
  const period = Math.max(2, Number(seconds) || 0) * 1000;
  hostTimer = setInterval(refreshHostPanels, period);
}

// refreshHostPanels redraws only the two host cards, in place.
//
// Re-rendering the whole dashboard would reset the scroll position and rebuild
// the relay tables every few seconds, which on a page an operator is reading is
// worse than slightly stale numbers.
async function refreshHostPanels() {
  if (state.view !== 'dashboard') { stopHostRefresh(); return; }
  // A console left open in a background tab should not keep polling: nobody is
  // reading the numbers, and the first thing the operator sees on returning is
  // the next tick's fresh reading anyway.
  if (document.hidden) return;
  const host = $('#view');
  if (!host || !host.querySelector('[data-host-panel]')) { stopHostRefresh(); return; }

  let info;
  try {
    info = await api('/api/v1/host');
  } catch (err) {
    // A single failed poll is not worth interrupting the operator for; the
    // next tick retries. Only a lost session matters, and api() handles that.
    return;
  }
  // The view may have been replaced while the request was in flight.
  const anchor = host.querySelector('[data-host-panel]');
  if (!anchor) { stopHostRefresh(); return; }
  anchor.replaceWith(hostPanel(info));
  const ping = host.querySelector('[data-host-ping]');
  if (ping) ping.replaceWith(hostPingPanel(info));
}

/* --------------------------------------------------------------- dashboard */

async function renderDashboard(host) {
  const status = await api('/api/v1/status');
  state.status = status;

  // Host telemetry is a separate request so that a host which cannot be
  // sampled — or an endpoint that is simply absent — degrades to one missing
  // panel instead of blanking the whole overview. The relay's own numbers are
  // the more important half of this page.
  let hostInfo = null;
  try {
    hostInfo = await api('/api/v1/host');
  } catch (err) {
    hostInfo = { available: false, reason: err.message };
  }

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

  host.append(hostPanel(hostInfo));
  host.append(hostPingPanel(hostInfo));

  if (server) {
    host.append(relayPanel(server));
  }
  if (client) {
    host.append(clientPanel(client));
  }

  // Keep the resource numbers live while the operator is looking at them. The
  // period comes from the server so the page cannot poll faster than the
  // sampler produces new values, which would only redraw identical numbers.
  const period = Number(hostInfo && hostInfo.pollSeconds) || 0;
  if (period > 0) startHostRefresh(period);
}

// small renders the value at label size. Hardware identity — a CPU model name,
// a kernel version — is prose, not a number, and at 22px monospace it overflows
// the card instead of being read.
function stat(label, value, unit, small) {
  const valueNode = el('div', { class: small ? 'value small' : 'value' }, [
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

/* -------------------------------------------------------------------- host */

/* Host telemetry. This is the machine the console runs on, not the relay's
 * peers: an operator's first question about a slow tunnel is whether the box
 * itself is the problem, and until now the console could only answer about the
 * relay. */

// Thresholds match the badge colours so a nearly-full disk and a busy CPU read
// the same way everywhere in the console.
function toneFor(pct) {
  const v = Number(pct) || 0;
  if (v >= 90) return 'bad';
  if (v >= 75) return 'warn';
  return '';
}

function usageBar(pct) {
  const v = Math.max(0, Math.min(100, Number(pct) || 0));
  return el('div', { class: 'usage' }, [
    el('div', { class: 'usage-fill ' + toneFor(v), style: `width:${v}%` }),
  ]);
}

function usageRow(name, pct, right, title) {
  return el('div', { class: 'usage-row' }, [
    el('div', { class: 'name', text: name, title: title || name }),
    usageBar(pct),
    el('div', { class: 'val', text: right }),
  ]);
}

// One narrow column per logical CPU. An average hides a single pegged core,
// which is exactly the shape a relay's encryption load takes on a small VPS.
function coreBars(list) {
  return el('div', { class: 'core-bars' }, list.map((pct) => {
    const v = Math.max(0, Math.min(100, Number(pct) || 0));
    return el('div', { class: 'core-bar', title: `${v}%` }, [
      el('i', { class: toneFor(v), style: `height:${v}%` }),
    ]);
  }));
}

function hostPanel(h) {
  const card = el('div', { class: 'card', 'data-host-panel': '' }, [el('h2', { text: '主机状态' })]);
  const fresh = h && h.pollSeconds
    ? `控制台所在这台机器的资源占用，每 ${h.pollSeconds} 秒采样一次。`
    : '控制台所在这台机器的资源占用。';
  card.append(el('p', { class: 'muted', text: fresh }));

  // An unsupported host is reported, never hidden: a missing panel and a panel
  // that says "this platform exposes nothing" are different facts.
  if (!h || !h.available) {
    card.append(el('div', { class: 'empty', text: (h && h.reason) || '此平台不支持主机资源采集' }));
    return card;
  }

  const cpu = h.cpu || {};
  const mem = h.memory || {};
  const swap = h.swap || {};
  const load = h.load || {};
  const net = h.network || {};
  const sys = h.system || {};

  card.append(el('div', { class: 'grid cols-4' }, [
    stat('CPU 使用率', (Number(cpu.usagePct) || 0).toFixed(1), '%'),
    stat('负载 (1 分钟)', (Number(load.one) || 0).toFixed(2)),
    stat('内存占用', (Number(mem.usagePct) || 0).toFixed(1), '%'),
    stat('进程数', num(sys.processCount), '个'),
  ]));

  const meters = el('div', {});
  const coreCount = Number(cpu.cores) || 0;
  meters.append(usageRow(
    'CPU',
    cpu.usagePct,
    `${(Number(cpu.usagePct) || 0).toFixed(1)}%${coreCount ? ` · ${coreCount} 核` : ''}`,
    cpu.model || 'CPU',
  ));
  meters.append(usageRow(
    '内存',
    mem.usagePct,
    `${bytes(mem.usedBytes)} / ${bytes(mem.totalBytes)}`,
    mem.availableBytes ? `可用 ${bytes(mem.availableBytes)}` : '',
  ));
  // Swap is only shown when the host actually has some: a row reading
  // "0 B / 0 B" on every machine without swap is noise.
  if (Number(swap.totalBytes) > 0) {
    meters.append(usageRow('交换分区', swap.usagePct, `${bytes(swap.usedBytes)} / ${bytes(swap.totalBytes)}`));
  }
  for (const d of h.disks || []) {
    const label = d.mount || d.device;
    const suffix = d.readOnly ? ' · 只读' : '';
    meters.append(usageRow(
      label,
      d.usagePct,
      `${bytes(d.usedBytes)} / ${bytes(d.totalBytes)}${suffix}`,
      `${d.device || ''} ${d.fstype || ''}`.trim(),
    ));
  }
  card.append(meters);

  if (cpu.perCorePct && cpu.perCorePct.length > 1) {
    card.append(el('h3', { text: '每核占用' }));
    card.append(coreBars(cpu.perCorePct));
  }

  const loadLine = `${(Number(load.one) || 0).toFixed(2)} / ${(Number(load.five) || 0).toFixed(2)} / ${(Number(load.fifteen) || 0).toFixed(2)}`;
  card.append(el('h3', { text: '网络与负载' }));
  card.append(el('div', { class: 'grid cols-4' }, [
    stat('下行速率', bytes(net.rxBytesPerSecond), '/s'),
    stat('上行速率', bytes(net.txBytesPerSecond), '/s'),
    stat('累计下行', bytes(net.rxBytes)),
    stat('累计上行', bytes(net.txBytes)),
  ]));
  card.append(el('div', { class: 'grid cols-4' }, [
    stat('负载 1/5/15', loadLine, '', true),
    stat('每核负载', (Number(load.perCore) || 0).toFixed(2)),
    stat('TCP 连接', num(net.tcpConnections), '条'),
    stat('TCP 监听', num(net.tcpListeners), '个'),
  ]));

  const errs = (Number(net.rxErrors) || 0) + (Number(net.txErrors) || 0);
  const drops = (Number(net.rxDropped) || 0) + (Number(net.txDropped) || 0);
  if (errs || drops) {
    // Only surfaced when non-zero: a permanent "0 errors" row trains an
    // operator to stop reading it, which is the opposite of its purpose.
    card.append(el('div', { class: 'notice warn', text: `网卡错误 ${num(errs)} 个，丢包 ${num(drops)} 个` }));
  }

  const thermal = (h.thermal || []).filter((t) => Number(t.tempC) > 0);
  if (thermal.length) {
    card.append(el('h3', { text: '温度' }));
    card.append(el('div', { class: 'grid cols-4' }, thermal.map((t) =>
      stat(t.label || t.zone, (Number(t.tempC) || 0).toFixed(1), '°C')
    )));
  }

  card.append(el('h3', { text: '硬件与系统' }));
  card.append(el('div', { class: 'grid cols-3' }, [
    stat('CPU 型号', cpu.model || '未知', '', true),
    stat('架构', cpu.arch || sys.arch || '未知', '', true),
    stat('主机名', sys.hostname || '未知', '', true),
    stat('操作系统', sys.distro || sys.os || '未知', '', true),
    stat('内核', sys.kernel || '未知', '', true),
    stat('虚拟化', sys.virtualization || '未知', '', true),
    stat('主机运行时长', duration(h.uptimeSeconds)),
    stat('逻辑核心', num(sys.numCpu), '个'),
    stat('CPU 频率', (Number(cpu.mhz) || 0).toFixed(0), 'MHz'),
  ]));

  return card;
}

function pingMethodLabel(method) {
  switch (method) {
    case 'icmp': return 'ICMP';
    case 'tcp': return 'TCP 握手';
    case 'mixed': return 'ICMP / TCP 混合';
    default: return '—';
  }
}

function hostPingPanel(h) {
  const ping = h.ping || {};
  const card = el('div', { class: 'card', 'data-host-ping': '' }, [
    el('h2', { text: '出网质量' }),
    el('p', {
      class: 'muted',
      text: '本机直连公网的延迟与丢包。它是「线路慢」和「这台机器出网慢」之间的分界线，与客户端到中转的握手延迟不是一回事。',
    }),
  ]);

  if (!ping.enabled) {
    card.append(el('div', { class: 'empty', text: '未启用（配置中的 host.pingTargets 为空）' }));
    return card;
  }

  // A round takes a few seconds and runs as soon as the monitor starts, so the
  // first page load can arrive before any result exists. Showing four zeroes
  // then would read as "the network is perfect" instead of "not measured yet",
  // which is the same class of lie as presenting a handshake as an ICMP trip.
  if (!ping.lastAt) {
    card.append(el('div', { class: 'empty', text: '正在测量…' }));
    return card;
  }

  card.append(el('div', { class: 'grid cols-4' }, [
    stat('平均延迟', (Number(ping.avgMs) || 0).toFixed(1), 'ms'),
    stat('最低延迟', (Number(ping.minMs) || 0).toFixed(1), 'ms'),
    stat('最高延迟', (Number(ping.maxMs) || 0).toFixed(1), 'ms'),
    stat('丢包率', (Number(ping.lossPct) || 0).toFixed(1), '%'),
  ]));

  const rows = (ping.targets || []).map((t) => {
    const loss = Number(t.lossPct) || 0;
    const lossCell = loss > 0
      ? el('td', {}, [el('span', { class: loss >= 50 ? 'badge bad' : 'badge warn', text: `${loss.toFixed(1)}%` })])
      : el('td', { class: 'mono', text: '0%' });
    return el('tr', {}, [
      el('td', { class: 'mono', text: t.address }),
      el('td', { text: pingMethodLabel(t.method) }),
      el('td', { text: num(t.sent) }),
      el('td', { text: num(t.recv) }),
      el('td', { class: 'mono', text: Number(t.recv) > 0 ? `${(Number(t.avgMs) || 0).toFixed(1)} ms` : '—' }),
      lossCell,
      t.error ? el('td', { class: 'muted small', text: t.error }) : el('td', { text: '—' }),
    ]);
  });

  card.append(el('div', { class: 'table-wrap' }, [
    el('table', {}, [
      el('thead', {}, [el('tr', {}, [
        el('th', { text: '目标' }), el('th', { text: '方式' }), el('th', { text: '发送' }),
        el('th', { text: '接收' }), el('th', { text: '平均延迟' }), el('th', { text: '丢包' }),
        el('th', { text: '备注' }),
      ])]),
      el('tbody', {}, rows),
    ]),
  ]));

  // The measurement method is stated because an ICMP round trip and a TCP
  // handshake to the same host are not comparable numbers, and a card that
  // showed one as the other would be quietly wrong.
  const notes = [`测量方式：${pingMethodLabel(ping.method)}`];
  if (ping.lastAt) notes.push(`最近探测：${shortTime(ping.lastAt)}`);
  card.append(el('p', { class: 'muted small', text: notes.join('　·　') }));
  if (ping.error) {
    card.append(el('div', { class: 'notice warn', text: ping.error }));
  }

  return card;
}

/* ------------------------------------------------------------------- guide */

// The guide is written for the console it is running in, not for the project in
// general: a server-side console and a client-side console are used by different
// people at different points of the same setup, and each needs the other half
// only as a handoff ("give these values to the client machine"), not as a full
// parallel tutorial. The mode decides which half is expanded.

// copyText copies to the clipboard, and tells the truth when it cannot.
//
// navigator.clipboard is only defined in a secure context, and this console is
// normally opened over plain HTTP at an IP address — so the modern API is
// usually absent here. A button that silently does nothing would be worse than
// no button, so the fallback selects the text and says what to press instead.
async function copyText(text, sourceNode) {
  try {
    if (navigator.clipboard && window.isSecureContext) {
      await navigator.clipboard.writeText(text);
      toast('已复制', 'ok');
      return;
    }
  } catch (_) { /* fall through to the manual path */ }

  try {
    const box = document.createElement('textarea');
    box.value = text;
    box.setAttribute('readonly', '');
    box.style.position = 'fixed';
    box.style.opacity = '0';
    document.body.append(box);
    box.select();
    const ok = document.execCommand('copy');
    box.remove();
    if (ok) { toast('已复制', 'ok'); return; }
  } catch (_) { /* fall through */ }

  // Last resort: leave the text selected so Ctrl+C does the rest. Saying this
  // is more useful than a failure toast with no next step.
  try {
    const range = document.createRange();
    range.selectNodeContents(sourceNode);
    const sel = window.getSelection();
    sel.removeAllRanges();
    sel.addRange(range);
  } catch (_) { /* nothing more we can do */ }
  toast('浏览器未授权自动复制，内容已选中，请按 Ctrl+C（Mac 为 ⌘C）', 'warn');
}

// code renders a command block with a copy button. Commands are the part of a
// tutorial that people get wrong by retyping, so each one is copyable as-is.
function code(text) {
  const pre = el('pre', { class: 'guide-code', text: text });
  const btn = el('button', {
    class: 'btn small ghost guide-copy',
    type: 'button',
    text: '复制',
    onclick: () => copyText(text, pre),
  });
  return el('div', { class: 'guide-codewrap' }, [pre, btn]);
}

function guideStep(n, title, nodes) {
  return el('section', { class: 'guide-step' }, [
    el('h3', {}, [
      el('span', { class: 'guide-num', text: String(n) }),
      title,
    ]),
    ...[].concat(nodes || []),
  ]);
}

function guideNote(kind, text) {
  return el('div', { class: 'notice' + (kind ? ' ' + kind : ''), text: text });
}

function guideTable(headers, rows) {
  return el('div', { class: 'table-wrap' }, [
    el('table', {}, [
      el('thead', {}, [el('tr', {}, headers.map((h) => el('th', { text: h })))]),
      el('tbody', {}, rows.map((r) => el('tr', {}, r.map((c) => el('td', { text: c }))))),
    ]),
  ]);
}

async function renderGuide(host) {
  clear(host);

  // The console address shown in the examples is this console's own address, so
  // the reader can paste the command instead of substituting a placeholder.
  // /api/v1/session does not carry it (it answers "who am I", not "where am I"),
  // so the status endpoint is asked; a failure only costs the sample address.
  let consoleURL = 'http://127.0.0.1:8787';
  try {
    const status = await api('/api/v1/status');
    if (status.webui && status.webui.url) consoleURL = status.webui.url;
  } catch (_) { /* the guide is readable without it */ }

  const session = state.session || {};
  const mode = session.mode || '';
  const username = session.username || 'admin';
  const isServer = mode === 'server' || mode === 'both';
  const isClient = mode === 'client' || mode === 'both';

  host.append(el('div', { class: 'card' }, [
    el('h2', { text: '使用说明' }),
    el('p', { class: 'muted', text: 'PortTransit 把「本地端口」的流量，经一台中转服务器转发到目标地址。'
      + '下面是从零到可用的完整流程；每一步都给出可以直接复制执行的命令。' }),
    el('div', { class: 'grid cols-3 guide-facts' }, [
      stat('当前模式', mode || '—', '', true),
      stat('控制台地址', consoleURL, '', true),
      stat('控制台账号', username, '', true),
    ]),
  ]));

  // --- What the two ends are ------------------------------------------------
  host.append(el('div', { class: 'card' }, [
    el('h2', { text: '先理解两个角色' }),
    guideTable(
      ['角色', '跑在哪里', '它做什么'],
      [
        ['中转服务端', '一台有公网 IP 的服务器', '监听中转端口，把流量转发到目标；本页控制台通常就跑在它上面'],
        ['客户端', '你自己的电脑 / 内网机器', '把本地端口的流量加密后送到中转服务端；可以配多条线路自动切换'],
      ],
    ),
    el('p', { class: 'muted small', text: '一句话：客户端负责「出去」，服务端负责「转发」。'
      + '两边的凭据必须对上——服务端安装时打印的那组 psk / uuid / publicKey 就是要填进客户端的东西。' }),
  ]));

  // --- Step 1: server -------------------------------------------------------
  if (isServer) {
    host.append(el('div', { class: 'card' }, [
      el('h2', { text: '安装与配置' }),
      guideStep(1, '在中转服务器上安装（本机已经装好了，这步是给新服务器的）', [
        el('p', { class: 'muted', text: '在 Debian / Ubuntu 上以 root 运行。装完会打印控制台地址、管理员密码，以及客户端要用的中转凭据——密码只显示一次。' }),
        code('curl -fsSL https://raw.githubusercontent.com/zhengwuji/duankouzhuanfa/main/scripts/install.sh | sudo bash'),
        el('p', { class: 'muted small', text: '想先看一遍脚本再执行，就把它下载下来：' }),
        code('wget https://raw.githubusercontent.com/zhengwuji/duankouzhuanfa/main/scripts/install.sh\nsudo bash install.sh --transport reality --port 443'),
        guideNote('', '已经装过的机器重新运行这个命令会先进管理菜单（查看状态、取凭据、改密码都在里面），不会直接覆盖。'),
      ]),
      guideStep(2, '把客户端要用的凭据取出来', [
        el('p', { class: 'muted', text: '凭据随时可以重新打印，不需要重装；REALITY 的 publicKey 由服务端保存的私钥现算，所以当时没抄下来也拿得回。' }),
        code('sudo porttransit show-credentials'),
        el('p', { class: 'muted small', text: '输出是 key=value 一行一项。这些值下一步要整体作为 JSON 填进客户端。' }),
      ]),
      guideStep(3, '确认端口在监听', [
        code('sudo systemctl status porttransit\nsudo ss -ltnp | grep porttransit'),
        el('p', { class: 'muted small', text: '「总览」页的「中转服务器」表里，每条线路都应该是「监听中」。'
          + '如果这里不亮，客户端连不上是必然的，先看「日志」页。' }),
      ]),
    ]));
  }

  // --- Step 2: client -------------------------------------------------------
  if (isClient) {
    host.append(el('div', { class: 'card' }, [
      el('h2', { text: '添加中转服务器' }),
      guideStep(isServer ? 4 : 1, '在客户端添加一条线路', [
        el('p', { class: 'muted', text: '打开「中转服务器」页 → 「+ 添加中转服务器」，填四个关键字段：' }),
        guideTable(
          ['字段', '填什么', '例子'],
          [
            ['名称', '自己认得出的名字', '上海中转'],
            ['服务器地址', '中转服务器的 IP 或域名 + 端口', '203.0.113.10:8443'],
            ['协议', '和服务端安装时选的保持一致', 'tls'],
            ['协议参数', '服务端打印的凭据，写成 JSON 对象', '见下面'],
          ],
        ),
        el('p', { class: 'muted small', text: '最常见的一个错误：凭据要整体作为一个 JSON 对象填进「协议参数」，不是一行一个字段。tls 线路长这样：' }),
        code('{ "psk": "base64:...", "insecure": true }'),
        el('p', { class: 'muted small', text: 'reality 线路长这样：' }),
        code('{ "psk": "...", "publicKey": "...", "shortId": "...", "serverName": "www.bing.com" }'),
        guideNote('warn', 'insecure: true 只是让自签证书不被拒绝。能拿到证书指纹时请改用 certFingerprint，那才是真正的校验。'),
      ]),
      guideStep(isServer ? 5 : 2, '验证这条线路通不通', [
        el('p', { class: 'muted', text: '在「中转服务器」列表里点那一行的「测试」，或者到「线路健康」页看自动探测的结果。' }),
        guideTable(
          ['看到什么', '说明什么', '怎么办'],
          [
            ['连通，延迟 12 ms', '握手成功，凭据是对的', '继续下一步'],
            ['失败：认证失败 / 握手失败', 'psk / uuid / publicKey 和服务端不一致', '重新 show-credentials 取一遍，逐字符核对'],
            ['失败：连接超时', '端口没开、防火墙挡了、或 IP 写错', '在服务端 ss -ltnp 确认监听，检查安全组与 ufw'],
            ['失败：证书错误', '协议或 serverName 不对', '协议要和安装时一致；reality 的 serverName 必须是服务端配的那个域名'],
          ],
        ),
      ]),
    ]));

    // --- Step 3: forwarding -------------------------------------------------
    host.append(el('div', { class: 'card' }, [
      el('h2', { text: '新建转发规则' }),
      guideStep(isServer ? 6 : 3, '把本地端口指到目标地址', [
        el('p', { class: 'muted', text: '打开「端口转发」页 → 「+ 新建转发」。填「本地监听地址」和「目标地址」两个端点，'
          + '中间走哪条线路由「指定服务器 / 分组」决定。' }),
        el('p', { class: 'muted small', text: '例一：把本机的 25565 转发到朋友的 Minecraft 服务器，走中转线路。' }),
        guideTable(
          ['本地监听地址', '目标地址', '传输类型'],
          [
            ['127.0.0.1:25565', 'mc.example.com:25565', 'TCP'],
          ],
        ),
        el('p', { class: 'muted small', text: '例二：从家里访问公司内网的远程桌面（目标在内网，只有客户端所在网络能到它）。' }),
        guideTable(
          ['本地监听地址', '目标地址', '传输类型'],
          [
            ['127.0.0.1:13389', '10.0.0.20:3389', 'TCP'],
          ],
        ),
        el('p', { class: 'muted small', text: '例三：转发 UDP（游戏、DNS 这类）。' }),
        guideTable(
          ['本地监听地址', '目标地址', '传输类型'],
          [
            ['127.0.0.1:5353', '8.8.8.8:53', 'UDP'],
          ],
        ),
        guideNote('warn', '新增或改动「监听端口」后需要重启客户端才会真正绑定端口；只改目标地址这类软配置会热生效。控制台保存时会提示这一点。'),
      ]),
      guideStep(isServer ? 7 : 4, '（可选）用本地代理代替逐条转发', [
        el('p', { class: 'muted', text: '不想一条条配端口时，客户端默认已经开了两个本地代理端口，所有流量按域名走线路：' }),
        guideTable(
          ['端口', '协议', '给谁用'],
          [
            ['127.0.0.1:1080', 'SOCKS5', '浏览器插件（SwitchyOmega 等）、Telegram、大多数软件'],
            ['127.0.0.1:8118', 'HTTP', '系统代理、curl、git'],
          ],
        ),
        code('curl --socks5 127.0.0.1:1080 https://ifconfig.me\ncurl --proxy  127.0.0.1:8118 https://ifconfig.me\nHTTPS_PROXY=http://127.0.0.1:8118 curl https://ifconfig.me'),
        el('p', { class: 'muted small', text: '第一个命令返回中转服务器的出口 IP，就说明整条链路通了。' }),
        guideNote('warn', '这两个代理默认没有密码，并且只绑定回环地址——它靠「只有本机能连」防护。'
          + '不要把 socks5Listen / httpListen 改成 0.0.0.0，那等于把你的出口代理开放给整个网络。'),
      ]),
    ]));
  }

  // --- What success looks like ---------------------------------------------
  host.append(el('div', { class: 'card' }, [
    el('h2', { text: '最后效果：怎么确认它在正常工作' }),
    el('p', { class: 'muted', text: '配好之后，控制台这几个地方应该同时是「对」的。任何一处不对，都能顺着它找到出问题的那一段。' }),
    guideTable(
      ['位置', '正常的样子', '它在告诉你'],
      [
        ['总览 → 活动连接', '有人用时会跳起来', '确实有流量在过中转，而不是只有配置'],
        ['总览 → 中转服务器表', '每条线路都是「监听中」，已接受在增长', '服务端端口开着，客户端握手成功'],
        ['总览 → 主机状态', 'CPU / 内存 / 磁盘有实时读数', '这台机器的资源还撑得住（控制台所在这台）'],
        ['总览 → 出网质量', '平均延迟几十毫秒内、丢包 0%', '这台机器自己的出网是好的'],
        ['线路健康', '每条线路「正常」，延迟稳定', '客户端 → 中转的握手质量'],
        ['日志', '没有持续刷屏的 error', '没有反复重连、认证失败这类暗病'],
      ],
    ),
    el('p', { class: 'muted small', text: '「出网质量」量的是控制台这台机器直连公网的质量，'
      + '「线路健康」量的是客户端到中转的握手延迟——两个数字回答的是不同问题，不要拿来互相解释。' }),
  ]));

  // --- Troubleshooting -----------------------------------------------------
  // Two of these rows differ by mode, and getting them wrong is the same defect
  // as the step split above: `install.sh` is the server installer, so telling a
  // client operator to run it sends them looking for a script that is not on
  // their disk.
  const trouble = [
    ['客户端连不上，日志刷「握手失败」', '凭据不一致', 'sudo porttransit show-credentials 重新取一遍'],
    ['端口测试超时', '防火墙 / 安全组没放行', '放行中转端口；服务端 ss -ltnp 确认在听'],
    ['转发规则保存了但不生效', '监听端口需要重启', '重启客户端进程'],
    ['升级后看不到新功能', '浏览器缓存了旧外壳', 'Ctrl/Cmd + Shift + R 强刷一次'],
  ];
  if (isServer) {
    trouble.push(
      ['控制台打不开', '监听地址是 127.0.0.1', 'porttransit set-console --listen 0.0.0.0:8787 --allow-remote 后重启'],
      ['忘了控制台密码', '密码只存哈希，找不回', 'sudo bash install.sh --reset-password'],
    );
  } else {
    trouble.push(
      ['控制台打不开', '监听地址是 127.0.0.1', 'porttransit show-console 看地址；本机访问即可，不必暴露到公网'],
      ['忘了控制台密码', '密码只存哈希，找不回', 'porttransit reset-password'],
    );
  }

  host.append(el('div', { class: 'card' }, [
    el('h2', { text: '卡住了怎么办' }),
    guideTable(['现象', '最可能的原因', '处理'], trouble),
    el('p', { class: 'muted small', text: '排查顺序建议从「服务端在不在听」开始，再到「客户端能不能握手」，最后才是「转发规则对不对」——'
      + '这个顺序每一步都能被上一步证伪，反过来查会同时在三个地方猜。' }),
    // Only offer views this mode actually has: a shortcut to a page whose nav
    // entry is hidden in this mode would look like the button is broken.
    el('div', { class: 'row' }, [
      el('button', { class: 'btn ghost', type: 'button', text: '看当前运行状态', onclick: () => show('dashboard') }),
      isClient ? el('button', { class: 'btn ghost', type: 'button', text: '看线路健康', onclick: () => show('health') }) : null,
      el('button', { class: 'btn ghost', type: 'button', text: '看日志', onclick: () => show('logs') }),
    ]),
  ]));
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
          if (!res.valid) toast('配置有问题：' + (res.errors || []).join('；'), 'bad');
          else if ((res.warnings || []).length) toast('校验通过，但有提醒：' + res.warnings.join('；'), 'warn');
          else toast('配置校验通过', 'ok');
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
      if ((res.warnings || []).length) {
        toast('配置校验通过，但有提醒：' + res.warnings.join('；'), 'warn');
        return;
      }
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
  // The dashboard is gone, so its poller must stop with it: otherwise it keeps
  // requesting a protected endpoint from the login screen and every tick throws
  // a 401 that the operator cannot act on.
  stopHostRefresh();
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

  // A server-only console has no client, and the relay/tunnel/health views all
  // read the client half of the configuration. Offering them produced a hard
  // 400 ("this process is not running a client") on click, which reads as a
  // broken console rather than as a feature this mode does not have.
  const mode = session.mode || '';
  const clientViews = ['servers', 'tunnels', 'health'];
  const hasClient = mode === 'client' || mode === 'both';
  for (const btn of document.querySelectorAll('.nav-item')) {
    if (clientViews.includes(btn.dataset.view)) btn.hidden = !hasClient;
  }
  // Land on a view this mode actually has.
  if (!hasClient && clientViews.includes(state.view)) state.view = 'dashboard';

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
  waitingOnLogin = true;
  try {
    await api('/api/v1/login', {
      method: 'POST',
      body: { username: $('#login-user').value, password: $('#login-pass').value },
    });
    await bootstrap();
  } catch (err) {
    errBox.textContent = err.message;
    errBox.hidden = false;
  } finally {
    waitingOnLogin = false;
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
