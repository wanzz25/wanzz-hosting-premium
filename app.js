const express = require('express');
const axios = require('axios');
const QRCode = require('qrcode');
const path = require('path');
const ssh2 = require('ssh2');
const crypto = require('crypto');
const config = require('./settings');

const app = express();
const PORT = process.env.PORT || 5000;

const panelsStorage = {};
const ipRequests = {};
const blockedIPs = new Set();
const REQUEST_LIMIT = 150;
const TIME_WINDOW = 60000;
const BLOCK_DURATION = 600000;
const ipBlockList = new Map();
const IP_BLOCK_DURATION = 86400000;

app.use(express.static('public'));
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

app.use((req, res, next) => {
  const clientIp = (req.headers['x-forwarded-for'] ? req.headers['x-forwarded-for'].split(',')[0] : req.socket.remoteAddress).trim();

  if (ipBlockList.has(clientIp)) {
    const blockData = ipBlockList.get(clientIp);
    if (Date.now() - blockData.timestamp < IP_BLOCK_DURATION) {
      return res.status(403).json({ error: 'Access denied. IP is blocked.', reason: blockData.reason });
    } else {
      ipBlockList.delete(clientIp);
    }
  }

  if (blockedIPs.has(clientIp)) {
    return res.status(403).json({ error: 'Access denied. IP blocked due to rate limiting.' });
  }

  const now = Date.now();
  if (!ipRequests[clientIp]) {
    ipRequests[clientIp] = [];
  }

  ipRequests[clientIp] = ipRequests[clientIp].filter(timestamp => now - timestamp < TIME_WINDOW);

  if (ipRequests[clientIp].length >= REQUEST_LIMIT) {
    blockedIPs.add(clientIp);
    setTimeout(() => blockedIPs.delete(clientIp), BLOCK_DURATION);
    return res.status(429).json({ error: 'Too many requests. IP blocked for 10 minutes.' });
  }

  ipRequests[clientIp].push(now);
  next();
});

function adminIPWhitelist(req, res, next) {
  const rawIp = req.socket.remoteAddress;
  const forwarded = req.headers['x-forwarded-for'];
  const clientIp = (forwarded ? forwarded.split(',')[0] : rawIp).trim();

  const whitelist = config.ADMIN_WHITELIST_IPS || [];

  if (whitelist.length === 0) {
    return next();
  }

  if (!whitelist.includes(clientIp)) {
    return res.status(403).render('admin-login', { 
      storeName: config.STORE_NAME, 
      error: 'Access denied. Your IP is not whitelisted.' 
    });
  }

  next();
}

function adminAuth(req, res, next) {
  const cookie = req.headers.cookie;
  if (cookie && cookie.includes('admin_token=' + config.ADMIN_PASSWORD)) {
    return next();
  }
  return res.status(403).render('admin-login', { storeName: config.STORE_NAME });
}

let cachedHardware = null;
let lastHardwareFetch = 0;

const GITHUB_API_URL = `https://api.github.com/repos/${config.GITHUB.OWNER}/${config.GITHUB.REPO}/contents/${config.GITHUB.FILE_PATH}`;
const AUTO_DELETE_AFTER_DAYS = config.AUTO_DELETE_AFTER_DAYS || 7;

let settingsCache = null;
let settingsLastFetch = 0;

const PAYMENT_SECRET_KEY = crypto.createHash('sha256').update(config.STORE_NAME + 'SECRET_KEY_2024').digest('hex').substring(0, 32);

async function loadSettings() {
  const now = Date.now();
  if (settingsCache && (now - settingsLastFetch) < 60000) {
    return settingsCache;
  }

  try {
    const githubData = await fetchData();
    const savedSettings = githubData.find(item => item.id === '_SETTINGS_');

    if (savedSettings && savedSettings.settings) {
      settingsCache = savedSettings.settings;
      settingsLastFetch = now;
      return settingsCache;
    }
  } catch (error) {}

  return {
    WEBSITE_LOGO: config.WEBSITE_LOGO,
    WEBSITE_BANNER: config.WEBSITE_BANNER,
    PRICES: config.PRICES,
    ANNOUNCEMENT: { text: '', active: false },
    MAINTENANCE_MODE: false,
    ADMIN_WHITELIST_IPS: config.ADMIN_WHITELIST_IPS || [],
    RESTOCK: false,
    OTHER_PRODUCTS: []
  };
}

async function saveSettings(newSettings) {
  try {
    const githubData = await fetchData();
    const settingsIndex = githubData.findIndex(item => item.id === '_SETTINGS_');

    if (settingsIndex !== -1) {
      githubData[settingsIndex].settings = newSettings;
    } else {
      githubData.push({
        id: '_SETTINGS_',
        settings: newSettings
      });
    }

    await updateData(githubData);
    settingsCache = newSettings;
    settingsLastFetch = Date.now();
    return true;
  } catch (error) {
    return false;
  }
}

async function fetchData() {
  try {
    const response = await fetch(GITHUB_API_URL, {
      headers: {
        'Authorization': `token ${config.GITHUB.TOKEN}`,
        'Cache-Control': 'no-cache'
      }
    });
    if (!response.ok) return [];
    const json = await response.json();
    const content = Buffer.from(json.content, 'base64').toString('utf-8');
    return JSON.parse(content);
  } catch (error) {
    return [];
  }
}

async function updateData(newData) {
  try {
    const current = await fetch(GITHUB_API_URL, {
      headers: { 'Authorization': `token ${config.GITHUB.TOKEN}` }
    }).then(res => res.json());

    const base64Content = Buffer.from(
      JSON.stringify(newData, null, 2)
    ).toString('base64');

    await fetch(GITHUB_API_URL, {
      method: 'PUT',
      headers: {
        'Authorization': `token ${config.GITHUB.TOKEN}`,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        message: 'Update dataserver.json via app',
        content: base64Content,
        sha: current.sha
      })
    });
  } catch (error) {}
}

async function getHardwareInfo() {
  const now = Date.now();
  if (cachedHardware && (now - lastHardwareFetch) < 300000) {
    return cachedHardware;
  }

  return new Promise((resolve) => {
    const conn = new ssh2.Client();

    if (!config.NODE.HOST || !config.NODE.ROOT_PASS) {
      return resolve({
        cpuModel: 'Not Configured',
        cpuCores: 0,
        cpuThreads: 0,
        cpuSpeed: '0.00',
        totalRam: 0,
        totalDisk: '0G',
        os: 'Unknown',
        uptime: 'Unknown',
        cpuUsage: 0,
        memoryUsage: 0,
        diskUsage: 0,
        memoryUsed: 0,
        memoryTotal: 0,
        diskUsed: 0,
        diskTotal: 0
      });
    }

    const data = {
      cpuModel: '',
      cpuCores: 0,
      cpuThreads: 0,
      cpuSpeed: '0.00',
      totalRam: 0,
      totalDisk: '',
      os: '',
      uptime: '',
      cpuUsage: 0,
      memoryUsage: 0,
      diskUsage: 0,
      memoryUsed: 0,
      memoryTotal: 0,
      diskUsed: 0,
      diskTotal: 0
    };

    conn.on('ready', () => {
      const commands = [
        { cmd: "sed -n 's/^model name[[:space:]]*: //p' /proc/cpuinfo | head -1", key: 'cpuModel' },
        { cmd: "grep 'cpu MHz' /proc/cpuinfo | awk '{sum+=$4;c++} END{if(c>0) printf \"%.2f\", sum/c/1000}'", key: 'cpuSpeed' },
        { cmd: "nproc", key: 'cpuThreads' },
        { cmd: "nproc", key: 'cpuCores' },
        { cmd: "free -m | awk '/Mem:/ {print $2}'", key: 'totalRam' },
        { cmd: "df -h --output=size / | tail -1 | tr -d ' '", key: 'totalDisk' },
        { cmd: "grep PRETTY_NAME /etc/os-release | cut -d= -f2 | tr -d '\"'", key: 'os' },
        { cmd: "uptime -p", key: 'uptime' },
        { cmd: "top -bn1 | grep '%Cpu' | awk '{print int(100-$8)}'", key: 'cpuUsage' },
        { cmd: "free -m | awk '/Mem:/ {print $3}'", key: 'memoryUsed' },
        { cmd: "df -BG --output=used / | tail -1 | tr -dc '0-9'", key: 'diskUsed' },
        { cmd: "df -BG --output=size / | tail -1 | tr -dc '0-9'", key: 'diskTotal' }
      ];

      let completed = 0;

      commands.forEach(({ cmd, key }) => {
        conn.exec(cmd, (err, stream) => {
          if (err) {
            completed++;
            if (completed === commands.length) finish();
            return;
          }

          let output = '';
          stream.on('data', chunk => output += chunk.toString());
          stream.on('close', () => {
            const clean = output.trim().replace(/\s+/g, ' ');

            switch (key) {
              case 'cpuModel':
                data.cpuModel = clean || 'Unknown';
                break;
              case 'cpuSpeed':
                data.cpuSpeed = (parseFloat(clean) || 0).toFixed(2);
                break;
              case 'cpuThreads':
                data.cpuThreads = parseInt(clean) || 0;
                break;
              case 'cpuCores':
                data.cpuCores = parseInt(clean) || 0;
                break;
              case 'totalRam':
                data.totalRam = parseInt(clean) || 0;
                data.memoryTotal = data.totalRam;
                break;
              case 'totalDisk':
                data.totalDisk = clean || '0G';
                break;
              case 'os':
                data.os = clean || 'Linux';
                break;
              case 'uptime':
                data.uptime = clean || 'Unknown';
                break;
              case 'cpuUsage':
                data.cpuUsage = Math.min(parseInt(clean) || 0, 100);
                break;
              case 'memoryUsed':
                data.memoryUsed = parseInt(clean) || 0;
                break;
              case 'diskUsed':
                data.diskUsed = parseInt(clean) || 0;
                break;
              case 'diskTotal':
                data.diskTotal = parseInt(clean) || 0;
                break;
            }

            completed++;
            if (completed === commands.length) finish();
          });
        });
      });

      function finish() {
        if (data.memoryTotal > 0) {
          data.memoryUsage = Math.round((data.memoryUsed / data.memoryTotal) * 100);
        } else {
          data.memoryUsage = 0;
        }

        if (data.diskTotal > 0) {
          data.diskUsage = Math.round((data.diskUsed / data.diskTotal) * 100);
        } else {
          data.diskUsage = 0;
        }

        cachedHardware = data;
        lastHardwareFetch = Date.now();
        conn.end();
        resolve(data);
      }
    }).on('error', () => {
      resolve({
        cpuModel: 'Connection Failed',
        cpuCores: 0,
        cpuThreads: 0,
        cpuSpeed: '0.00',
        totalRam: 0,
        totalDisk: '0G',
        os: 'Unknown',
        uptime: 'Unknown',
        cpuUsage: 0,
        memoryUsage: 0,
        diskUsage: 0,
        memoryUsed: 0,
        memoryTotal: 0,
        diskUsed: 0,
        diskTotal: 0
      });
    }).connect({
      host: config.NODE.HOST,
      port: 22,
      username: 'root',
      password: config.NODE.ROOT_PASS,
      readyTimeout: 20000
    });
  });
}

app.get('/api/server-stats', async (req, res) => {
  try {
    const [nodeResponse, serversResponse, userResponse, hardwareInfo] = await Promise.all([
      axios.get(
        `${config.PTERODACTYL.DOMAIN}/api/application/nodes`,
        {
          headers: {
            'Authorization': `Bearer ${config.PTERODACTYL.API_KEY}`,
            'Accept': 'application/json'
          },
          timeout: 10000
        }
      ).catch(() => ({ data: { data: [] } })),

      axios.get(
        `${config.PTERODACTYL.DOMAIN}/api/application/servers`,
        {
          headers: {
            'Authorization': `Bearer ${config.PTERODACTYL.API_KEY}`,
            'Accept': 'application/json'
          },
          timeout: 10000
        }
      ).catch(() => ({ data: { data: [] } })),

      axios.get(
        `${config.PTERODACTYL.DOMAIN}/api/application/users`,
        {
          headers: {
            'Authorization': `Bearer ${config.PTERODACTYL.API_KEY}`,
            'Accept': 'application/json'
          },
          timeout: 10000
        }
      ).catch(() => ({ data: { data: [] } })),

      getHardwareInfo()
    ]);

    const serverCount = serversResponse.data.data ? serversResponse.data.data.length : 0;
    const userCount = userResponse.data.data ? userResponse.data.data.length : 0;

    res.json({
      success: true,
      stats: {
        servers: serverCount,
        users: userCount,
        hardware: {
          cpuModel: hardwareInfo.cpuModel,
          cpuCores: hardwareInfo.cpuCores,
          cpuThreads: hardwareInfo.cpuThreads,
          cpuSpeed: hardwareInfo.cpuSpeed,
          totalRam: hardwareInfo.totalRam,
          totalDisk: hardwareInfo.totalDisk,
          os: hardwareInfo.os,
          uptime: hardwareInfo.uptime
        },
        resources: {
          cpu: {
            used: hardwareInfo.cpuUsage,
            total: hardwareInfo.cpuThreads,
            percent: hardwareInfo.cpuUsage
          },
          memory: {
            used: hardwareInfo.memoryUsed,
            total: hardwareInfo.memoryTotal,
            percent: hardwareInfo.memoryUsage
          },
          disk: {
            used: hardwareInfo.diskUsed,
            total: hardwareInfo.diskTotal,
            percent: hardwareInfo.diskUsage
          }
        },
        status: 'online',
        timestamp: new Date().toISOString()
      }
    });

  } catch (error) {
    const hardwareInfo = await getHardwareInfo();
    res.json({
      success: true,
      stats: {
        servers: 0,
        users: 0,
        hardware: {
          cpuModel: hardwareInfo.cpuModel,
          cpuCores: hardwareInfo.cpuCores,
          cpuThreads: hardwareInfo.cpuThreads,
          cpuSpeed: hardwareInfo.cpuSpeed,
          totalRam: hardwareInfo.totalRam,
          totalDisk: hardwareInfo.totalDisk,
          os: hardwareInfo.os,
          uptime: hardwareInfo.uptime
        },
        resources: {
          cpu: { 
            used: hardwareInfo.cpuUsage, 
            total: hardwareInfo.cpuThreads, 
            percent: hardwareInfo.cpuUsage 
          },
          memory: { 
            used: hardwareInfo.memoryUsed, 
            total: hardwareInfo.memoryTotal, 
            percent: hardwareInfo.memoryUsage 
          },
          disk: { 
            used: hardwareInfo.diskUsed, 
            total: hardwareInfo.diskTotal, 
            percent: hardwareInfo.diskUsage 
          }
        },
        status: 'offline',
        timestamp: new Date().toISOString()
      }
    });
  }
});

async function loadServerDatabase() {
  try {
    const data = await fetchData();
    return data.filter(item => item.id !== '_SETTINGS_');
  } catch (err) {
    return [];
  }
}

async function saveServerDatabase(data) {
  try {
    const currentSettings = await loadSettings();
    const fullData = [
      ...data,
      {
        id: '_SETTINGS_',
        settings: currentSettings
      }
    ];
    await updateData(fullData);
  } catch (err) {}
}

app.get('/admin', adminIPWhitelist, adminAuth, async (req, res) => {
  try {
    let storedPanels = await loadServerDatabase();
    let isDatabaseUpdated = false;
    let enrichedServers = [];

    let stats = { total: 0, active: 0, suspended: 0, expired: 0 };

    try {
      const response = await axios.get(
        `${config.PTERODACTYL.DOMAIN}/api/application/servers?include=user`,
        {
          headers: {
            'Authorization': `Bearer ${config.PTERODACTYL.API_KEY}`,
            'Accept': 'application/json'
          },
          timeout: 15000
        }
      );

      if (response.data.data) {
        stats.total = response.data.data.length;

        enrichedServers = response.data.data.map(server => {
          const attr = server.attributes;

          const serverId = attr.id;
          const serverName = attr.name;
          const serverNode = attr.node;
          const isRealSuspended = attr.suspended;

          const limits = attr.limits;
          const ramDisplay = limits.memory === 0 ? 'Unlimited' : (limits.memory >= 1000 ? `${limits.memory / 1000}GB` : `${limits.memory}MB`);
          const cpuDisplay = limits.cpu === 0 ? 'Unlimited' : `${limits.cpu}%`;
          const diskDisplay = limits.disk === 0 ? 'Unlimited' : (limits.disk >= 1000 ? `${limits.disk / 1000}GB` : `${limits.disk}MB`);

          const ownerAttr = attr.relationships?.user?.attributes;
          const ownerUsername = ownerAttr ? ownerAttr.username : `User_${attr.user}`;
          const ownerEmail = ownerAttr ? ownerAttr.email : "No Email";

          let storedPanel = storedPanels.find(p => p.panel_data && p.panel_data.server_id === serverId);
          const now = Date.now();
          const createdTime = new Date(attr.created_at).getTime();

          if (!storedPanel) {
            const defaultDays = 30;
            const expiresAtTime = createdTime + (defaultDays * 24 * 60 * 60 * 1000);

            const newServerEntry = {
              id: `AUTO-${serverId}`,
              username: ownerUsername,
              product_name: `Imported Server`,
              days: defaultDays,
              password: "N/A (External)",
              created_at: attr.created_at,
              status: 'active',
              suspend_by: null,
              panel_data: {
                server_id: serverId,
                server_name: serverName,
                owner_id: attr.user,
                owner_email: ownerEmail,
                username: ownerUsername,
                password: "N/A",
                expires_at: new Date(expiresAtTime).toISOString(),
                specs: { ram: ramDisplay, cpu: cpuDisplay, disk: diskDisplay, ram_raw: limits.memory, disk_raw: limits.disk, cpu_raw: limits.cpu }
              }
            };
            storedPanels.push(newServerEntry);
            storedPanel = newServerEntry;
            isDatabaseUpdated = true;
          }

          const activeDays = Math.floor((now - createdTime) / (1000 * 60 * 60 * 24));

          let expiresAt;
          if (storedPanel.panel_data.expires_at) {
             expiresAt = new Date(storedPanel.panel_data.expires_at).getTime();
          } else {
             expiresAt = createdTime + (storedPanel.days * 24 * 60 * 60 * 1000);
          }
          const daysLeft = Math.ceil((expiresAt - now) / (1000 * 60 * 60 * 24));

          let statusCode = 'active';
          let statusText = '';
          let statusColor = 'green'; 

          const localSuspendBy = storedPanel.suspend_by;

          if (isRealSuspended) {
              if (localSuspendBy === 'admin') {
                  statusCode = 'admin_locked';
                  statusColor = 'red';
                  statusText = 'LOCKED BY ADMIN';
                  stats.suspended++;
              } else {
                  statusCode = 'suspended';
                  statusColor = 'yellow';
                  statusText = 'SUSPENDED';
                  stats.suspended++;
              }
          } else {
              if (daysLeft <= 0) {
                  statusCode = 'expired_running';
                  statusColor = 'red';
                  statusText = 'EXPIRED (Running)';
                  stats.expired++;
              } else {
                  statusCode = 'active';
                  statusColor = 'green';
                  statusText = 'RUNNING';
                  stats.active++;
              }
          }

          return {
            serverId: serverId,
            name: serverName,
            user: ownerUsername,
            node: serverNode,
            activeDays: activeDays,
            daysLeft: daysLeft,
            expiresAt: storedPanel.panel_data.expires_at,
            statusCode: statusCode,
            statusColor: statusColor,
            statusText: statusText,
            specs: storedPanel.panel_data.specs || { ram: ramDisplay, cpu: cpuDisplay, disk: diskDisplay },
            limits: { memory: limits.memory, cpu: limits.cpu, disk: limits.disk }
          };
        });

        if (isDatabaseUpdated) await saveServerDatabase(storedPanels);
      }
    } catch (apiError) {}

    const settings = await loadSettings();
    const blockedIPsList = Array.from(ipBlockList.entries()).map(([ip, data]) => ({
      ip,
      timestamp: data.timestamp,
      reason: data.reason,
      timeLeft: Math.ceil((IP_BLOCK_DURATION - (Date.now() - data.timestamp)) / 60000)
    }));

    res.render('dash-admin', { 
      storeName: config.STORE_NAME,
      panels: storedPanels,
      pterodactylServers: enrichedServers,
      PT_DOMAIN: config.PTERODACTYL.DOMAIN,
      stats: stats,
      settings: settings,
      blockedIPs: blockedIPsList
    });
  } catch (error) {
    res.status(500).send('Internal Error');
  }
});

app.post('/admin/addtime', adminIPWhitelist, adminAuth, async (req, res) => {
  try {
    const { idserver, days } = req.body;
    const addDays = parseInt(days);

    if (!idserver || isNaN(addDays)) return res.status(400).json({ success: false, message: 'Invalid params.' });

    const db = await loadServerDatabase();
    const idx = db.findIndex(p => p.panel_data && p.panel_data.server_id == idserver);

    if (idx === -1) return res.status(404).json({ success: false, message: 'Server not found.' });

    const srv = db[idx];
    let currentExpire = new Date(srv.panel_data.expires_at).getTime();
    if (currentExpire < Date.now()) currentExpire = Date.now();

    const newExpire = currentExpire + (addDays * 24 * 60 * 60 * 1000);
    srv.panel_data.expires_at = new Date(newExpire).toISOString();
    srv.days = (parseInt(srv.days) || 0) + addDays;

    delete srv.suspend_by; 

    db[idx] = srv;
    await saveServerDatabase(db);

    try {
        await axios.post(`${config.PTERODACTYL.DOMAIN}/api/application/servers/${idserver}/unsuspend`, {}, {
            headers: { 'Authorization': `Bearer ${config.PTERODACTYL.API_KEY}`, 'Accept': 'application/json' }
        });
    } catch (e) {}

    res.json({ success: true, message: 'Time added & Unsuspended.', new_expiry: srv.panel_data.expires_at });
  } catch (error) {
    res.status(500).json({ success: false });
  }
});

app.post('/admin/deltime', adminIPWhitelist, adminAuth, async (req, res) => {
  try {
    const { idserver, days } = req.body;
    const delDays = parseInt(days);

    if (!idserver || isNaN(delDays)) return res.status(400).json({ success: false });

    const db = await loadServerDatabase();
    const idx = db.findIndex(p => p.panel_data && p.panel_data.server_id == idserver);

    if (idx === -1) return res.status(404).json({ success: false });

    const srv = db[idx];
    let currentExpire = new Date(srv.panel_data.expires_at).getTime();
    const newExpire = currentExpire - (delDays * 24 * 60 * 60 * 1000);

    srv.panel_data.expires_at = new Date(newExpire).toISOString();
    let newTotal = (parseInt(srv.days) || 0) - delDays;
    srv.days = newTotal > 0 ? newTotal : 0;

    db[idx] = srv;
    await saveServerDatabase(db);

    res.json({ success: true, message: 'Time reduced.', new_expiry: srv.panel_data.expires_at });
  } catch (error) {
    res.status(500).json({ success: false });
  }
});

app.post('/admin/suspend', adminIPWhitelist, adminAuth, async (req, res) => {
  try {
    const { idserver } = req.body;
    if (!idserver) return res.status(400).json({ success: false });

    await axios.post(`${config.PTERODACTYL.DOMAIN}/api/application/servers/${idserver}/suspend`, {}, {
        headers: { 'Authorization': `Bearer ${config.PTERODACTYL.API_KEY}`, 'Accept': 'application/json' }
    });

    const db = await loadServerDatabase();
    const idx = db.findIndex(p => p.panel_data && p.panel_data.server_id == idserver);
    if (idx !== -1) {
        db[idx].suspend_by = 'admin';
        await saveServerDatabase(db);
    }

    res.json({ success: true, message: 'Suspended by Admin.' });
  } catch (error) {
    res.status(500).json({ success: false });
  }
});

app.post('/admin/unsuspend', adminIPWhitelist, adminAuth, async (req, res) => {
  try {
    const { idserver } = req.body;
    if (!idserver) return res.status(400).json({ success: false });

    await axios.post(`${config.PTERODACTYL.DOMAIN}/api/application/servers/${idserver}/unsuspend`, {}, {
        headers: { 'Authorization': `Bearer ${config.PTERODACTYL.API_KEY}`, 'Accept': 'application/json' }
    });

    const db = await loadServerDatabase();
    const idx = db.findIndex(p => p.panel_data && p.panel_data.server_id == idserver);
    if (idx !== -1) {
        delete db[idx].suspend_by;
        await saveServerDatabase(db);
    }

    res.json({ success: true, message: 'Unsuspended.' });
  } catch (error) {
    res.status(500).json({ success: false });
  }
});

app.post('/admin/upgrade-specs', adminIPWhitelist, adminAuth, async (req, res) => {
  try {
    const { serverId, specs } = req.body;
    
    if (!serverId || !specs) {
      return res.status(400).json({ success: false, message: 'Server ID and specs required' });
    }

    const specMap = {
      '1gb': { ram: 1024, disk: 3000, cpu: 100 },
      '2gb': { ram: 2048, disk: 6000, cpu: 190 },
      '3gb': { ram: 3072, disk: 7000, cpu: 250 },
      '4gb': { ram: 4096, disk: 9000, cpu: 290 },
      '5gb': { ram: 5120, disk: 13000, cpu: 330 },
      '6gb': { ram: 6144, disk: 15000, cpu: 450 },
      '7gb': { ram: 7168, disk: 17000, cpu: 500 },
      'unli': { ram: 0, disk: 0, cpu: 0 }
    };

    const selectedSpec = specMap[specs.toLowerCase()];
    if (!selectedSpec) {
      return res.status(400).json({ success: false, message: 'Invalid specs' });
    }

    const response = await axios.patch(
      `${config.PTERODACTYL.DOMAIN}/api/application/servers/${serverId}/build`,
      {
        allocation: 1,
        memory: selectedSpec.ram,
        swap: 0,
        disk: selectedSpec.disk,
        io: 500,
        cpu: selectedSpec.cpu,
        threads: null,
        feature_limits: {
          databases: 5,
          allocations: 1,
          backups: 5
        }
      },
      {
        headers: {
          Authorization: `Bearer ${config.PTERODACTYL.API_KEY}`,
          "Content-Type": "application/json",
          Accept: "application/json"
        }
      }
    );

    const db = await loadServerDatabase();
    const idx = db.findIndex(p => p.panel_data && p.panel_data.server_id == serverId);
    
    if (idx !== -1) {
      const ramDisplay = selectedSpec.ram === 0 ? 'Unlimited' : `${selectedSpec.ram / 1000}GB`;
      const diskDisplay = selectedSpec.disk === 0 ? 'Unlimited' : `${selectedSpec.disk / 1000}GB`;
      const cpuDisplay = selectedSpec.cpu === 0 ? 'Unlimited' : `${selectedSpec.cpu}%`;
      
      db[idx].panel_data.specs = {
        ram: ramDisplay,
        disk: diskDisplay,
        cpu: cpuDisplay,
        ram_raw: selectedSpec.ram,
        disk_raw: selectedSpec.disk,
        cpu_raw: selectedSpec.cpu
      };
      
      let productName = '';
      if (specs.toLowerCase() === '1gb') productName = 'Panel 1GB RAM';
      else if (specs.toLowerCase() === '2gb') productName = 'Panel 2GB RAM';
      else if (specs.toLowerCase() === '3gb') productName = 'Panel 3GB RAM';
      else if (specs.toLowerCase() === '4gb') productName = 'Panel 4GB RAM';
      else if (specs.toLowerCase() === '5gb') productName = 'Panel 5GB RAM';
      else if (specs.toLowerCase() === '6gb') productName = 'Panel 6GB RAM';
      else if (specs.toLowerCase() === '7gb') productName = 'Panel 7GB RAM';
      else if (specs.toLowerCase() === 'unli') productName = 'Panel UNLIMITED';
      
      db[idx].product_name = productName;
      
      await saveServerDatabase(db);
    }

    res.json({ 
      success: true, 
      message: `Successfully upgraded to ${specs.toUpperCase()} specs`,
      specs: selectedSpec
    });
  } catch (err) {
    console.log("Upgrade failed:", err.response?.data || err.message);
    res.status(500).json({ 
      success: false, 
      message: err.response?.data?.message || err.message || 'Upgrade failed'
    });
  }
});

app.post('/admin/block-ip', adminIPWhitelist, adminAuth, (req, res) => {
  try {
    const { ip, reason } = req.body;

    if (!ip) {
      return res.status(400).json({ success: false, message: 'IP address required' });
    }

    ipBlockList.set(ip, {
      timestamp: Date.now(),
      reason: reason || 'Blocked by admin'
    });

    res.json({ success: true, message: `IP ${ip} has been blocked` });
  } catch (error) {
    res.status(500).json({ success: false, message: error.message });
  }
});

app.post('/admin/unblock-ip', adminIPWhitelist, adminAuth, (req, res) => {
  try {
    const { ip } = req.body;

    if (!ip) {
      return res.status(400).json({ success: false, message: 'IP address required' });
    }

    if (ipBlockList.has(ip)) {
      ipBlockList.delete(ip);
      res.json({ success: true, message: `IP ${ip} has been unblocked` });
    } else {
      res.json({ success: false, message: `IP ${ip} not found in block list` });
    }
  } catch (error) {
    res.status(500).json({ success: false, message: error.message });
  }
});

app.post('/admin/clear-blocked-ips', adminIPWhitelist, adminAuth, (req, res) => {
  try {
    ipBlockList.clear();
    res.json({ success: true, message: 'All blocked IPs have been cleared' });
  } catch (error) {
    res.status(500).json({ success: false, message: error.message });
  }
});

app.get('/admin/blocked-ips', adminIPWhitelist, adminAuth, (req, res) => {
  try {
    const blockedIPsList = Array.from(ipBlockList.entries()).map(([ip, data]) => ({
      ip,
      timestamp: data.timestamp,
      reason: data.reason,
      timeLeft: Math.ceil((IP_BLOCK_DURATION - (Date.now() - data.timestamp)) / 60000)
    }));

    res.json({ success: true, blockedIPs: blockedIPsList });
  } catch (error) {
    res.status(500).json({ success: false, message: error.message });
  }
});

app.post('/admin/save-other-product', adminIPWhitelist, adminAuth, async (req, res) => {
  try {
    const { product } = req.body;
    const settings = await loadSettings();

    const otherProducts = settings.OTHER_PRODUCTS || [];
    const existingIndex = otherProducts.findIndex(p => p.id === product.id);

    if (existingIndex !== -1) {
      otherProducts[existingIndex] = product;
    } else {
      otherProducts.push(product);
    }

    settings.OTHER_PRODUCTS = otherProducts;
    await saveSettings(settings);

    res.json({ success: true, message: 'Product saved successfully' });
  } catch (error) {
    res.status(500).json({ success: false, message: error.message });
  }
});

app.post('/admin/delete-other-product', adminIPWhitelist, adminAuth, async (req, res) => {
  try {
    const { productId } = req.body;
    const settings = await loadSettings();

    settings.OTHER_PRODUCTS = (settings.OTHER_PRODUCTS || []).filter(p => p.id !== productId);
    await saveSettings(settings);

    res.json({ success: true, message: 'Product deleted successfully' });
  } catch (error) {
    res.status(500).json({ success: false, message: error.message });
  }
});

async function deleteExpiredPanel(serverId, username) {
  try {
    let ownerId = null;

    try {
      const infoResponse = await axios.get(
        `${config.PTERODACTYL.DOMAIN}/api/application/servers/${serverId}`,
        {
          headers: {
            'Authorization': `Bearer ${config.PTERODACTYL.API_KEY}`,
            'Accept': 'application/json'
          }
        }
      );
      ownerId = infoResponse.data.attributes.user;
    } catch (e) {}

    if (ownerId) {
      try {
        await axios.delete(
          `${config.PTERODACTYL.DOMAIN}/api/application/servers/${serverId}`,
          {
            headers: {
              'Authorization': `Bearer ${config.PTERODACTYL.API_KEY}`,
              'Accept': 'application/json'
            }
          }
        );
      } catch (apiError) {}

      try {
        const userCheck = await axios.get(
          `${config.PTERODACTYL.DOMAIN}/api/application/users/${ownerId}?include=servers`,
          {
            headers: { 'Authorization': `Bearer ${config.PTERODACTYL.API_KEY}`, 'Accept': 'application/json' }
          }
        );

        const userAttr = userCheck.data.attributes;
        const userServers = userAttr.relationships?.servers?.data || [];
        const remainingServers = userServers.filter(s => s.attributes.id != serverId);

        if (!userAttr.root_admin && remainingServers.length === 0) {
          await axios.delete(
            `${config.PTERODACTYL.DOMAIN}/api/application/users/${ownerId}`,
            {
              headers: { 'Authorization': `Bearer ${config.PTERODACTYL.API_KEY}`, 'Accept': 'application/json' }
            }
          );
        }
      } catch (err) {}
    }

    for (const [key, panel] of Object.entries(panelsStorage)) {
      if (panel.panel_data && panel.panel_data.server_id == serverId) {
        delete panelsStorage[key];
        break;
      }
    }

    return true;
  } catch (error) {
    return false;
  }
}

setInterval(async () => {
    try {
        const db = await loadServerDatabase();
        const now = Date.now();
        let dbChanged = false;
        let suspendCount = 0;
        let deleteCount = 0;
        const panelsToDelete = [];

        for (let i = 0; i < db.length; i++) {
            const srv = db[i];

            if (srv.suspend_by === 'admin') continue;

            const expireTime = new Date(srv.panel_data.expires_at).getTime();
            const daysExpired = Math.floor((now - expireTime) / (1000 * 60 * 60 * 24));

            if (expireTime < now && srv.suspend_by !== 'auto') {
                const sId = srv.panel_data.server_id;
                try {
                    await axios.post(`${config.PTERODACTYL.DOMAIN}/api/application/servers/${sId}/suspend`, {}, {
                        headers: { 'Authorization': `Bearer ${config.PTERODACTYL.API_KEY}`, 'Accept': 'application/json' }
                    });

                    srv.suspend_by = 'auto';
                    dbChanged = true;
                    suspendCount++;
                } catch (err) {}
            }

            if (expireTime < now && daysExpired >= AUTO_DELETE_AFTER_DAYS) {
                panelsToDelete.push({
                    index: i,
                    serverId: srv.panel_data.server_id,
                    username: srv.username
                });
            }
        }

        for (const panel of panelsToDelete.reverse()) {
            const success = await deleteExpiredPanel(panel.serverId, panel.username);
            if (success) {
                db.splice(panel.index, 1);
                dbChanged = true;
                deleteCount++;
            }
        }

        if (dbChanged) await saveServerDatabase(db);

    } catch (err) {}
}, 60 * 1000);

app.post('/admin/login', adminIPWhitelist, (req, res) => {
  const { password } = req.body;
  if (password === config.ADMIN_PASSWORD) {
    res.cookie('admin_token', password, { httpOnly: true, maxAge: 3600000 });
    res.redirect('/admin');
  } else {
    res.render('admin-login', { storeName: config.STORE_NAME, error: 'Password salah' });
  }
});

app.post('/admin/create-panel', adminIPWhitelist, adminAuth, async (req, res) => {
  try {
    const { username, product, days, password } = req.body;
    if (!username || !product) throw new Error('Username dan product diperlukan');

    const durationDays = parseInt(days) || 30;
    const orderId = `ADMIN-${Date.now()}`;
    const generatedPassword = password || generatePassword();
    const panelData = await createRealPterodactylPanel({
        username: username,
        product_name: product,
        days: durationDays,
        password: generatedPassword
    });
    const newServerData = {
      id: orderId,
      username: username,
      product_name: product,
      days: durationDays,
      password: generatedPassword,
      created_at: new Date().toISOString(),
      status: 'active',
      panel_data: {
          ...panelData,
          expires_at: new Date(Date.now() + (durationDays * 24 * 60 * 60 * 1000)).toISOString()
      }
    };
    const currentDatabase = await loadServerDatabase();
    currentDatabase.push(newServerData);
    await saveServerDatabase(currentDatabase);

    if (typeof panelsStorage !== 'undefined') {
        panelsStorage[orderId] = newServerData;
    }

    res.json({ success: true, panel_data: panelData });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

app.get('/api/config', async (req, res) => {
  try {
    const referer = req.headers.referer || req.headers.origin;
    if (!referer || !referer.includes(req.headers.host)) {
      return res.status(403).json({ error: 'Access denied' });
    }

    const settings = await loadSettings();

    res.json({
      success: true,
      storeName: config.STORE_NAME,
      websiteLogo: settings.WEBSITE_LOGO || config.WEBSITE_LOGO,
      websiteBanner: settings.WEBSITE_BANNER || config.WEBSITE_BANNER,
      channelLink: config.CHANNEL_LINK,
      botGroupLink: config.BOT_GROUP_LINK,
      storeGroupLink: config.STORE_GROUP_LINK,
      contactAdmin: config.CONTACT_ADMIN,
      announcement: settings.ANNOUNCEMENT || { text: '', active: false },
      maintenanceMode: settings.MAINTENANCE_MODE || false,
      restock: settings.RESTOCK || false,
      prices: settings.PRICES || config.PRICES,
      otherProducts: settings.OTHER_PRODUCTS || []
    });
  } catch (error) {
    res.status(500).json({ success: false, error: 'Configuration error' });
  }
});

app.post('/admin/api/save-settings', adminIPWhitelist, adminAuth, async (req, res) => {
  try {
    const { logo, banner, announcement, announcementActive, maintenanceMode, restock, prices, otherProducts } = req.body;

    const currentSettings = await loadSettings();

    const newSettings = {
      WEBSITE_LOGO: logo || currentSettings.WEBSITE_LOGO || config.WEBSITE_LOGO,
      WEBSITE_BANNER: banner || currentSettings.WEBSITE_BANNER || config.WEBSITE_BANNER,
      PRICES: prices || currentSettings.PRICES || config.PRICES,
      ANNOUNCEMENT: {
        text: announcement || '',
        active: announcementActive === 'true' || announcementActive === true
      },
      MAINTENANCE_MODE: maintenanceMode === 'true' || maintenanceMode === true,
      RESTOCK: restock === 'true' || restock === true,
      ADMIN_WHITELIST_IPS: config.ADMIN_WHITELIST_IPS || [],
      OTHER_PRODUCTS: otherProducts || currentSettings.OTHER_PRODUCTS || []
    };

    const saved = await saveSettings(newSettings);

    if (saved) {
      res.json({ success: true, message: 'Settings saved successfully' });
    } else {
      res.status(500).json({ success: false, message: 'Failed to save settings' });
    }
  } catch (error) {
    res.status(500).json({ success: false, message: error.message });
  }
});

function generatePaymentSignature(orderId, amount, timestamp) {
  const data = `${orderId}:${amount}:${timestamp}:${PAYMENT_SECRET_KEY}`;
  return crypto.createHash('sha256').update(data).digest('hex');
}

function verifyPaymentSignature(orderId, amount, timestamp, signature) {
  const expectedSignature = generatePaymentSignature(orderId, amount, timestamp);
  return expectedSignature === signature;
}

const validatePrice = (req, res, next) => {
  try {
    const settingsPromise = loadSettings();

    settingsPromise.then(settings => {
      const priceMap = settings.PRICES || config.PRICES;

      if (req.body.product_id && priceMap) {
        let basePrice = 0;

        if (req.body.product_id === 'panel-1gb') basePrice = priceMap.PANEL_1GB || 3000;
        else if (req.body.product_id === 'panel-2gb') basePrice = priceMap.PANEL_2GB || 5000;
        else if (req.body.product_id === 'panel-3gb') basePrice = priceMap.PANEL_3GB || 7000;
        else if (req.body.product_id === 'panel-4gb') basePrice = priceMap.PANEL_4GB || 9000;
        else if (req.body.product_id === 'panel-5gb') basePrice = priceMap.PANEL_5GB || 11000;
        else if (req.body.product_id === 'panel-6gb') basePrice = priceMap.PANEL_6GB || 14000;
        else if (req.body.product_id === 'panel-7gb') basePrice = priceMap.PANEL_7GB || 18000;
        else if (req.body.product_id === 'panel-premium') basePrice = priceMap.PANEL_PREMIUM || 30000;

        const days = parseInt(req.body.days) || 30;
        const pricePerDay = basePrice / 30;
        const calculatedPrice = Math.ceil(pricePerDay * days);

        if (req.body.amount && parseInt(req.body.amount) !== calculatedPrice) {
          return res.status(400).json({ 
            success: false, 
            error: 'Invalid price calculation',
            expected: calculatedPrice,
            received: parseInt(req.body.amount),
            base_price: basePrice,
            days: days,
            price_per_day: pricePerDay
          });
        }

        req.calculatedPrice = calculatedPrice;
        req.basePrice = basePrice;
        req.pricePerDay = pricePerDay;
      }
      next();
    }).catch(() => {
      next();
    });
  } catch (error) {
    res.status(500).json({ success: false, error: 'Price validation failed' });
  }
};

app.post('/api/create-qris', validatePrice, async (req, res) => {
  try {
    const settings = await loadSettings();

    if (settings.RESTOCK && req.body.type !== 'renewal') {
      return res.status(400).json({ 
        success: false,
        error: 'MODE RESTOCK: Saat ini hanya bisa memperpanjang panel yang sudah ada'
      });
    }

    const { order_id, username, product_name, days, product_id, type = 'new', password } = req.body;

    if (!order_id || !product_id || !username) {
      return res.status(400).json({ 
        success: false,
        error: 'Order ID, product ID, dan username diperlukan' 
      });
    }

    const amount = req.calculatedPrice || req.basePrice;
    const timestamp = Date.now();
    const signature = generatePaymentSignature(order_id, amount, timestamp);

    const payload = {
      project: config.PAYMENT.SLUG,
      order_id: order_id,
      amount: amount,
      api_key: config.PAYMENT.API_KEY,
      signature: signature,
      timestamp: timestamp
    };

    const response = await axios.post(
      'https://app.pakasir.com/api/transactioncreate/qris',
      payload,
      { 
        headers: { 
          'Content-Type': 'application/json',
          'Accept': 'application/json'
        },
        timeout: 15000
      }
    );

    panelsStorage[order_id] = {
      order_id,
      username,
      product_id,
      product_name: product_name || product_id,
      basePrice: req.basePrice,
      calculatedPrice: amount,
      days: parseInt(days) || 30,
      amount: amount,
      status: 'pending',
      created_at: new Date().toISOString(),
      panel_data: null,
      payment_data: response.data.payment,
      type: type,
      signature: signature,
      timestamp: timestamp,
      payment_attempts: 0,
      last_check: Date.now(),
      password: password 
    };

    let qrImage = '';
    if (response.data.payment?.payment_number) {
      try {
        qrImage = await QRCode.toDataURL(response.data.payment.payment_number, {
          width: 300,
          margin: 2,
          color: {
            dark: '#000000',
            light: '#FFFFFF'
          }
        });
      } catch (qrError) {}
    }

    res.json({
      success: true,
      payment: response.data.payment,
      qr_image: qrImage,
      order_id: order_id,
      amount: amount
    });

  } catch (error) {
    res.status(500).json({ 
      success: false,
      error: error.response?.data?.error || 'Gagal membuat QRIS'
    });
  }
});


app.get('/api/check-payment', async (req, res) => {
  try {
    const { order_id } = req.query;
    const clientIp = (req.headers['x-forwarded-for'] ? req.headers['x-forwarded-for'].split(',')[0] : req.socket.remoteAddress).trim();

    if (!order_id) {
      return res.status(400).json({ 
        success: false,
        error: 'Order ID diperlukan' 
      });
    }

    const orderData = panelsStorage[order_id];

    if (!orderData) {
      return res.status(404).json({
        success: false,
        error: 'Order tidak ditemukan'
      });
    }

    if (orderData.payment_attempts > 30) {
      return res.json({
        success: true,
        transaction: { status: 'timeout' },
        order_status: 'timeout',
        message: 'Payment timeout'
      });
    }

    orderData.payment_attempts = (orderData.payment_attempts || 0) + 1;
    orderData.last_check = Date.now();

    const amount = orderData.amount;
    const url = `https://app.pakasir.com/api/transactiondetail?project=${config.PAYMENT.SLUG}&amount=${amount}&order_id=${order_id}&api_key=${config.PAYMENT.API_KEY}`;

    const response = await axios.get(url, {
      headers: { 'Accept': 'application/json' },
      timeout: 10000
    });

    const transaction = response.data?.transaction;
    let panelData = null;

    if (transaction?.status === 'completed' && !orderData.panel_data) {
      const verifySignature = verifyPaymentSignature(
        order_id, 
        amount, 
        orderData.timestamp, 
        orderData.signature
      );

      if (!verifySignature) {
        ipBlockList.set(clientIp, {
          timestamp: Date.now(),
          reason: 'Payment signature manipulation detected'
        });
        return res.status(403).json({ 
          success: false, 
          error: 'Invalid payment signature' 
        });
      }

      try {
        if (orderData.type === 'renewal') {
          panelData = await renewPanel(orderData);
        } else {
          panelData = await createRealPterodactylPanel(orderData);
        }

        orderData.panel_data = panelData;
        orderData.status = 'completed';
        orderData.completed_at = new Date().toISOString();
        orderData.transaction = transaction;

        try {
          let currentDb = await loadServerDatabase();
          if (orderData.type === 'renewal') {
            const existingIdx = currentDb.findIndex(p => 
              p.panel_data && p.panel_data.server_id == orderData.server_id
            );
            if (existingIdx !== -1) {
              currentDb[existingIdx].days = (parseInt(currentDb[existingIdx].days) || 0) + orderData.days;
              currentDb[existingIdx].panel_data.expires_at = panelData.new_expiry;
            }
          } else {
            const newServerEntry = {
              id: `ORDER-${order_id}`,
              username: panelData.username, 
              product_name: orderData.product_name,
              days: parseInt(orderData.days) || 30,
              password: panelData.password, 
              created_at: panelData.created_at,
              status: 'active',
              panel_data: panelData
            };
            currentDb.push(newServerEntry);
          }
          await saveServerDatabase(currentDb);
        } catch (dbError) {}
      } catch (panelError) {        
        orderData.status = 'completed'; 
        orderData.completed_at = new Date().toISOString();
        orderData.transaction = transaction;
        orderData.panel_error = panelError.message;

        return res.json({
          success: true,
          transaction: transaction,
          panel_data: null,
          panel_error: panelError.message
        });
      }
    } else if (orderData.panel_data) {      
      panelData = orderData.panel_data;
    }

    res.json({
      success: true,
      transaction: transaction,
      panel_data: panelData,
      order_status: orderData.status
    });

  } catch (error) {    
    const orderData = panelsStorage[req.query.order_id];
    if (orderData?.status === 'completed') {
      return res.json({
        success: true,
        transaction: { status: 'completed' },
        panel_data: orderData.panel_data,
        order_status: 'completed'
      });
    }

    res.status(500).json({ 
      success: false,
      error: 'Gagal memeriksa status pembayaran'
    });
  }
});

async function createRealPterodactylPanel(orderData) {
  const { username, product_name, days = 30 } = orderData;
  const password = orderData.password || generatePassword(); 
  const email = username + '@gmail.com';
  const name = username.charAt(0).toUpperCase() + username.slice(1) + ' Server';
  const specs = {
    'Panel 1GB RAM': { ram: '1500', disk: '3000', cpu: '100' },
    'Panel 2GB RAM': { ram: '3500', disk: '6000', cpu: '190' },
    'Panel 3GB RAM': { ram: '4000', disk: '7000', cpu: '250' },
    'Panel 4GB RAM': { ram: '5000', disk: '9000', cpu: '290' },
    'Panel 5GB RAM': { ram: '6000', disk: '13000', cpu: '330' },
    'Panel 6GB RAM': { ram: '7000', disk: '15000', cpu: '450' },
    'Panel 7GB RAM': { ram: '8000', disk: '17000', cpu: '500' },
    'Panel UNLIMITED': { ram: '0', disk: '0', cpu: '0' }
  };

  let specKey = product_name;
  if (product_name.includes('1GB')) specKey = 'Panel 1GB RAM';
  else if (product_name.includes('2GB')) specKey = 'Panel 2GB RAM';
  else if (product_name.includes('3GB')) specKey = 'Panel 3GB RAM';
  else if (product_name.includes('4GB')) specKey = 'Panel 4GB RAM';
  else if (product_name.includes('5GB')) specKey = 'Panel 5GB RAM';
  else if (product_name.includes('6GB')) specKey = 'Panel 6GB RAM';
  else if (product_name.includes('7GB')) specKey = 'Panel 7GB RAM';
  else if (product_name.includes('UNLIMITED') || product_name.includes('UNLI')) specKey = 'Panel UNLIMITED';

  const spec = specs[specKey] || specs['Panel 1GB RAM'];
  const ram = spec.ram;
  const disknya = spec.disk;
  const cpu = spec.cpu;

  const checkUserRes = await axios.get(
    `${config.PTERODACTYL.DOMAIN}/api/application/users?filter[username]=${username}`,
    {
      headers: {
        'Authorization': `Bearer ${config.PTERODACTYL.API_KEY}`,
        'Accept': 'application/json'
      },
      timeout: 10000
    }
  );

  if (checkUserRes.data.data && checkUserRes.data.data.length > 0) {
    const existingUser = checkUserRes.data.data[0].attributes;
    throw new Error(`Username ${existingUser.username} sudah terdaftar.`);
  }
  const userRes = await axios.post(
    `${config.PTERODACTYL.DOMAIN}/api/application/users`,
    {
      email: email,
      username: username,
      first_name: name,
      last_name: 'Server',
      language: 'en',
      password: password
    },
    {
      headers: {
        'Authorization': `Bearer ${config.PTERODACTYL.API_KEY}`,
        'Accept': 'application/json',
        'Content-Type': 'application/json'
      },
      timeout: 15000
    }
  );

  if (userRes.data.errors) {
    throw new Error(`Gagal membuat user: ${JSON.stringify(userRes.data.errors[0])}`);
  }
  const user = userRes.data.attributes;
  const userId = user.id;

  const eggRes = await axios.get(
    `${config.PTERODACTYL.DOMAIN}/api/application/nests/${config.PTERODACTYL.NEST_ID}/eggs/${config.PTERODACTYL.EGG_ID}`,
    {
      headers: {
        'Authorization': `Bearer ${config.PTERODACTYL.API_KEY}`,
        'Accept': 'application/json'
      },
      timeout: 10000
    }
  );

  if (eggRes.data.errors) {
    throw new Error(`Gagal mengambil egg details: ${JSON.stringify(eggRes.data.errors[0])}`);
  }
  const startupCmd = eggRes.data.attributes?.startup || 'npm start';

  const serverPayload = {
    name: name,
    description: `Server dibuat pada ${new Date().toLocaleDateString('id-ID')}`,
    user: userId,
    egg: parseInt(config.PTERODACTYL.EGG_ID),
    docker_image: 'ghcr.io/parkervcp/yolks:nodejs_20',
    startup: startupCmd,
    environment: {
      INST: 'npm',
      USER_UPLOAD: '0',
      AUTO_DELETE: '0',
      CMD_RUN: 'npm start'
    },
    limits: {
      memory: parseInt(ram),
      swap: 0,
      disk: parseInt(disknya),
      io: 500,
      cpu: parseInt(cpu)
    },
    feature_limits: {
      databases: 5,
      backups: 5,
      allocations: 5
    },
    deploy: {
      locations: [parseInt(config.PTERODACTYL.LOCATION_ID)],
      dedicated_ip: false,
      port_range: []
    }
  };

  const serverRes = await axios.post(
    `${config.PTERODACTYL.DOMAIN}/api/application/servers`,
    serverPayload,
    {
      headers: {
        'Authorization': `Bearer ${config.PTERODACTYL.API_KEY}`,
        'Accept': 'application/json',
        'Content-Type': 'application/json'
      },
      timeout: 30000
    }
  );

  if (serverRes.data.errors) {
    throw new Error(`Gagal membuat server: ${JSON.stringify(serverRes.data.errors[0])}`);
  }
  const server = serverRes.data.attributes;
  const expiresAt = Date.now() + (days * 24 * 60 * 60 * 1000);
  const expiryDate = new Date(expiresAt).toLocaleString('id-ID', { timeZone: 'Asia/Jakarta' });

  return {
    username: user.username,
    password: password,
    email: user.email,
    panel_url: config.PTERODACTYL.DOMAIN,
    server_id: server.id,
    server_name: server.name,
    created_at: new Date().toISOString(),
    expires_at: new Date(expiresAt).toISOString(), 
    expiry_date: expiryDate,
    days: days,
    specs: {
      ram: ram === '0' ? 'Unlimited' : `${parseInt(ram) / 1000}GB`,
      disk: disknya === '0' ? 'Unlimited' : `${parseInt(disknya) / 1000}GB`,
      cpu: cpu === '0' ? 'Unlimited' : `${cpu}%`,
      ram_raw: ram,
      disk_raw: disknya,
      cpu_raw: cpu
    },
    raw_data: {
      user: user,
      server: server
    }
  };
}

function generatePassword() {
  const chars = 'abcdefghijklmnopqrstuvwxyz0123456789';
  let password = '';
  for (let i = 0; i < 8; i++) {
    password += chars.charAt(Math.floor(Math.random() * chars.length));
  }
  return password;
}

app.post('/api/manual-check', async (req, res) => {
  try {
    const { order_id } = req.body;

    if (!order_id) {
      return res.status(400).json({ 
        success: false,
        error: 'Order ID diperlukan' 
      });
    }

    const orderData = panelsStorage[order_id];

    if (!orderData) {
      return res.status(404).json({
        success: false,
        error: 'Order tidak ditemukan'
      });
    }

    const amount = orderData.amount;
    const url = `https://app.pakasir.com/api/transactiondetail?project=${config.PAYMENT.SLUG}&amount=${amount}&order_id=${order_id}&api_key=${config.PAYMENT.API_KEY}`;

    const response = await axios.get(url, {
      headers: { 'Accept': 'application/json' },
      timeout: 10000
    });

    const transaction = response.data?.transaction;
    let panelData = null;

    if (transaction?.status === 'completed') {
      if (!orderData.panel_data) {
        try {
          if (orderData.type === 'renewal') {
            panelData = await renewPanel(orderData);
          } else {
            panelData = await createRealPterodactylPanel(orderData);
          }

          orderData.panel_data = panelData;
          orderData.status = 'completed';
          orderData.completed_at = new Date().toISOString();
          orderData.transaction = transaction;
        } catch (panelError) {
          orderData.status = 'completed';
          orderData.completed_at = new Date().toISOString();
          orderData.transaction = transaction;
          orderData.panel_error = panelError.message;

          return res.json({
            success: true,
            transaction: transaction,
            panel_data: null,
            panel_error: panelError.message
          });
        }
      } else {
        panelData = orderData.panel_data;
      }
    }

    res.json({
      success: true,
      transaction: transaction,
      panel_data: panelData,
      order_status: orderData.status
    });

  } catch (error) {
    const orderData = panelsStorage[req.body.order_id];
    if (orderData?.status === 'completed') {
      return res.json({
        success: true,
        transaction: { status: 'completed' },
        panel_data: orderData.panel_data,
        order_status: 'completed'
      });
    }

    res.status(500).json({ 
      success: false,
      error: 'Gagal memeriksa pembayaran'
    });
  }
});

app.post('/api/force-create-panel', adminIPWhitelist, adminAuth, async (req, res) => {
  try {
    const { order_id, username, password, product_name, days } = req.body;

    if (!username || !product_name) {
      return res.status(400).json({ 
        success: false,
        error: 'Username dan product name diperlukan' 
      });
    }

    const orderData = panelsStorage[order_id] || {
      username,
      product_name,
      password: password || generatePassword(),
      days: days || 30
    };

    const panelData = await createRealPterodactylPanel(orderData);

    if (panelsStorage[order_id]) {
      panelsStorage[order_id].panel_data = panelData;
      panelsStorage[order_id].status = 'completed';
      panelsStorage[order_id].completed_at = new Date().toISOString();
    } else {
      panelsStorage[order_id] = {
        order_id,
        username,
        product_name,
        panel_data: panelData,
        status: 'completed',
        completed_at: new Date().toISOString()
      };
    }

    res.json({
      success: true,
      panel_data: panelData,
      message: 'Panel berhasil dibuat secara manual'
    });

  } catch (error) {
    res.status(500).json({ 
      success: false,
      error: 'Gagal membuat panel: ' + error.message
    });
  }
});

app.post('/api/cancel-payment', (req, res) => {
  try {
    const { order_id } = req.body;

    if (!order_id) {
      return res.status(400).json({ 
        success: false,
        error: 'Order ID diperlukan' 
      });
    }

    if (panelsStorage[order_id]) {
      delete panelsStorage[order_id];
    }

    res.json({
      success: true,
      message: 'Transaksi dibatalkan',
      order_id: order_id
    });

  } catch (error) {
    res.status(500).json({ 
      success: false,
      error: 'Gagal membatalkan'
    });
  }
});

app.get('/api/order/:order_id', (req, res) => {
  try {
    const { order_id } = req.params;
    const orderData = panelsStorage[order_id];

    if (!orderData) {
      return res.status(404).json({
        success: false,
        error: 'Order tidak ditemukan'
      });
    }

    let safePanelData = null;
    if (orderData.panel_data) {
      safePanelData = {
        username: orderData.panel_data.username,
        server_id: orderData.panel_data.server_id,
        server_name: orderData.panel_data.server_name,
        expires_at: orderData.panel_data.expires_at,
        specs: orderData.panel_data.specs
      };
    }

    res.json({
      success: true,
      order: {
        order_id: orderData.order_id,
        username: orderData.username,
        product_name: orderData.product_name,
        amount: orderData.amount,
        status: orderData.status,
        created_at: orderData.created_at,
        completed_at: orderData.completed_at,
        panel_data: safePanelData,
        panel_error: orderData.panel_error
      }
    });

  } catch (error) {
    res.status(500).json({ 
      success: false,
      error: 'Gagal mengambil data order'
    });
  }
});

app.get('/api/panels', adminIPWhitelist, adminAuth, (req, res) => {
  try {
    const activePanels = Object.values(panelsStorage)
      .filter(panel => panel.status === 'completed' && panel.panel_data)
      .map(panel => ({
        order_id: panel.order_id,
        username: panel.username,
        product_name: panel.product_name,
        created_at: panel.created_at,
        panel_data: panel.panel_data
      }));

    res.json({
      success: true,
      count: activePanels.length,
      panels: activePanels
    });

  } catch (error) {
    res.status(500).json({ 
      success: false,
      error: 'Gagal mengambil data panel'
    });
  }
});

app.post('/admin/api/panels/delete/:serverId', adminIPWhitelist, adminAuth, async (req, res) => {
  try {
    const serverId = req.params.serverId;
    let apiMessage = '';
    let apiSuccess = false;
    let ownerId = null;

    try {
        const infoResponse = await axios.get(
            `${config.PTERODACTYL.DOMAIN}/api/application/servers/${serverId}`,
            {
                headers: {
                    'Authorization': `Bearer ${config.PTERODACTYL.API_KEY}`,
                    'Accept': 'application/json'
                }
            }
        );
        ownerId = infoResponse.data.attributes.user;
    } catch (e) {
        const currentDb = await loadServerDatabase();
        const localData = currentDb.find(p => p.panel_data && p.panel_data.server_id == serverId);
        if (localData && localData.panel_data.owner_id) {
            ownerId = localData.panel_data.owner_id;
        }
    }

    try {
      const deleteResponse = await axios.delete(
        `${config.PTERODACTYL.DOMAIN}/api/application/servers/${serverId}`,
        {
          headers: {
            'Authorization': `Bearer ${config.PTERODACTYL.API_KEY}`,
            'Accept': 'application/json'
          }
        }
      );

      if (deleteResponse.status === 204) {
        apiSuccess = true;
        apiMessage = 'Server berhasil dihapus dari Pterodactyl';
      }
    } catch (apiError) {
      if (apiError.response?.status === 404) {
        apiMessage = 'Server tidak ditemukan di Pterodactyl (mungkin sudah dihapus)';
        apiSuccess = true;
      } else {
        apiMessage = `Gagal menghapus dari Pterodactyl: ${apiError.message}`;
      }
    }

    let ownerMessage = 'Owner masih memiliki server lain.';
    if (ownerId && apiSuccess) {
        try {
            const userCheck = await axios.get(
                `${config.PTERODACTYL.DOMAIN}/api/application/users/${ownerId}?include=servers`,
                {
                    headers: { 'Authorization': `Bearer ${config.PTERODACTYL.API_KEY}`, 'Accept': 'application/json' }
                }
            );

            const userAttr = userCheck.data.attributes;
            const userServers = userAttr.relationships?.servers?.data || [];

            const remainingServers = userServers.filter(s => s.attributes.id != serverId);

            if (userAttr.root_admin) {
                ownerMessage = 'Owner adalah Admin (tidak dihapus).';
            } 
            else if (remainingServers.length === 0) {
                await axios.delete(
                    `${config.PTERODACTYL.DOMAIN}/api/application/users/${ownerId}`,
                    {
                        headers: { 'Authorization': `Bearer ${config.PTERODACTYL.API_KEY}`, 'Accept': 'application/json' }
                    }
                );
                ownerMessage = 'Owner tidak memiliki server lagi & telah dihapus.';
            }
        } catch (err) {
            ownerMessage = 'Gagal memproses pembersihan owner.';
        }
    }

    let localDeleted = false;
    const currentDb = await loadServerDatabase();

    const serverIndex = currentDb.findIndex(p => p.panel_data && p.panel_data.server_id == serverId);

    if (serverIndex !== -1) {
        currentDb.splice(serverIndex, 1);
        await saveServerDatabase(currentDb);
        localDeleted = true;
    }

    for (const [key, panel] of Object.entries(panelsStorage)) {
      if (panel.panel_data && panel.panel_data.server_id == serverId) {
        delete panelsStorage[key];
        break;
      }
    }

    res.json({ 
      success: true, 
      message: 'Proses penghapusan selesai',
      api_message: apiMessage,
      owner_status: ownerMessage,
      local_db_deleted: localDeleted
    });

  } catch (error) {
    res.status(500).json({ 
      success: false, 
      error: error.message 
    });
  }
});

app.get('/health', (req, res) => {
  res.json({
    status: 'OK',
    service: config.STORE_NAME,
    timestamp: new Date().toISOString(),
    active_panels: Object.keys(panelsStorage).filter(id => panelsStorage[id].status === 'completed').length,
    pending_panels: Object.keys(panelsStorage).filter(id => panelsStorage[id].status === 'pending').length
  });
});

app.get('/api/debug', adminIPWhitelist, adminAuth, (req, res) => {
  res.json({
    storage_count: Object.keys(panelsStorage).length,
    env_configured: {
      PT_DOMAIN: !!config.PTERODACTYL.DOMAIN,
      PT_API_KEY: !!config.PTERODACTYL.API_KEY,
      PAKASIR_SLUG: !!config.PAYMENT.SLUG
    }
  });
});

app.get('/api/dashboard-stats', async (req, res) => {
  try {
    const storageData = Object.values(panelsStorage);
    const today = new Date().toDateString();

    const storageStats = {
      total: storageData.filter(p => p.status === 'completed' && p.panel_data).length,
      active: storageData.filter(p => p.status === 'completed' && p.panel_data).length,
      today: storageData.filter(p => 
        p.status === 'completed' && 
        p.panel_data && 
        new Date(p.completed_at || p.created_at).toDateString() === today
      ).length
    };

    let pterodactylStats = { total: 0, active: 0, today: 0 };

    try {
      const response = await axios.get(
        `${config.PTERODACTYL.DOMAIN}/api/application/servers`,
        {
          headers: {
            'Authorization': `Bearer ${config.PTERODACTYL.API_KEY}`,
            'Accept': 'application/json'
          },
          timeout: 15000
        }
      );

      if (response.data?.data) {
        const servers = response.data.data;
        pterodactylStats.total = servers.length;
        pterodactylStats.active = servers.length;
        pterodactylStats.today = servers.filter(s => 
          new Date(s.attributes.created_at).toDateString() === today
        ).length;
      }
    } catch (apiError) {}

    res.json({
      success: true,
      stats: {
        storage: storageStats,
        pterodactyl: pterodactylStats,
        combined: {
          total: pterodactylStats.total || storageStats.total,
          active: pterodactylStats.active || storageStats.active,
          today: pterodactylStats.today || storageStats.today
        }
      }
    });
  } catch (error) {
    res.status(500).json({ 
      success: false, 
      error: 'Gagal mengambil statistik dashboard' 
    });
  }
});

app.get('/api/panels-database', adminIPWhitelist, adminAuth, async (req, res) => {
  try {
    const db = await loadServerDatabase();
    res.json({
      success: true,
      count: db.length,
      panels: db
    });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

app.get('/api/server-details/:serverId', adminIPWhitelist, adminAuth, async (req, res) => {
  try {
    const { serverId } = req.params;
    const response = await axios.get(
      `${config.PTERODACTYL.DOMAIN}/api/application/servers/${serverId}?include=user`,
      {
        headers: {
          'Authorization': `Bearer ${config.PTERODACTYL.API_KEY}`,
          'Accept': 'application/json'
        }
      }
    );
    res.json(response.data.attributes);
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

app.delete('/admin/api/database-panel/:panelId', adminIPWhitelist, adminAuth, async (req, res) => {
  try {
    const { panelId } = req.params;
    const db = await loadServerDatabase();
    const initialLength = db.length;

    const filteredDb = db.filter(panel => panel.id !== panelId);

    if (filteredDb.length === initialLength) {
      return res.status(404).json({ success: false, message: 'Panel not found' });
    }

    await saveServerDatabase(filteredDb);
    res.json({ success: true, message: 'Panel deleted from database' });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

app.get('/api/check-username/:username', async (req, res) => {
  try {
    const { username } = req.params;

    if (!/^[a-z0-9]{3,20}$/.test(username)) {
      return res.json({
        success: true,
        available: false,
        message: 'Format username tidak valid (harus 3-20 karakter, huruf kecil dan angka)'
      });
    }

    const response = await axios.get(
      `${config.PTERODACTYL.DOMAIN}/api/application/users?filter[username]=${username}`,
      {
        headers: {
          'Authorization': `Bearer ${config.PTERODACTYL.API_KEY}`,
          'Accept': 'application/json'
        },
        timeout: 10000
      }
    );

    const isAvailable = !response.data.data || response.data.data.length === 0;

    res.json({
      success: true,
      available: isAvailable,
      message: isAvailable ? 'Username tersedia' : `Username ${username} sudah terdaftar.`
    });
  } catch (error) {
    res.status(500).json({ 
      success: false, 
      error: 'Gagal memeriksa username' 
    });
  }
});

app.post('/api/calculate-price', validatePrice, (req, res) => {
  try {
    res.json({
      success: true,
      basePrice: req.basePrice,
      calculatedPrice: req.calculatedPrice,
      days: parseInt(req.body.days) || 30
    });
  } catch (error) {
    res.status(500).json({ success: false, error: 'Price calculation failed' });
  }
});

app.get('/api/check-server/:username', async (req, res) => {
  try {
    const { username } = req.params;

    const db = await loadServerDatabase();
    const server = db.find(panel => 
      panel.username === username || 
      (panel.panel_data && panel.panel_data.username === username)
    );

    if (!server) {
      return res.json({
        success: false,
        error: 'Server tidak ditemukan dengan username tersebut'
      });
    }

    const now = new Date();
    const expiresAt = new Date(server.panel_data.expires_at);
    const daysLeft = Math.ceil((expiresAt - now) / (1000 * 60 * 60 * 24));

    const settings = await loadSettings();
    const priceMap = settings.PRICES || config.PRICES;

    res.json({
      success: true,
      server: {
        username: server.username,
        server_id: server.panel_data.server_id,
        server_name: server.panel_data.server_name,
        product_name: server.product_name,
        expires_at: server.panel_data.expires_at,
        days_left: daysLeft,
        specs: server.panel_data.specs || {},
        suspend_by: server.suspend_by || null
      }
    });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

async function renewPanel(orderData) {
  try {
    try {
      const panelInfo = await axios.get(
        `${config.PTERODACTYL.DOMAIN}/api/application/servers/${orderData.server_id}`,
        {
          headers: {
            Authorization: `Bearer ${config.PTERODACTYL.API_KEY}`,
            Accept: "application/json"
          }
        }
      );

      const realLimits = panelInfo.data.attributes.limits;
      const realRam = realLimits.memory;

      const dbSync = await loadServerDatabase();
      const syncIndex = dbSync.findIndex(
        p => p.panel_data && p.panel_data.server_id == orderData.server_id
      );

      if (syncIndex !== -1) {
        dbSync[syncIndex].panel_data.specs = {
          ...dbSync[syncIndex].panel_data.specs,
          ram_raw: realRam,
          ram: realRam === 0 ? "Unlimited" : `${realRam / 1000}GB`
        };

        await saveServerDatabase(dbSync);
      }
    } catch (e) {
      console.log("SYNC RAM FAILED:", e.message);
    }
    const db = await loadServerDatabase();

    const serverIndex = db.findIndex(p =>
      p.panel_data && p.panel_data.server_id == orderData.server_id
    );

    if (serverIndex === -1 && orderData.username) {
      const byUser = db.findIndex(p =>
        p.username === orderData.username ||
        (p.panel_data && p.panel_data.username === orderData.username)
      );

      if (byUser !== -1) {
        orderData.server_id = db[byUser].panel_data.server_id;
        return renewPanel(orderData);
      }
    }

    if (serverIndex === -1)
      throw new Error("Server tidak ditemukan di database");

    const server = db[serverIndex];
    const specs = server.panel_data.specs || {};
    const ram = specs.ram_raw || specs.ram;

    let productId = "panel-1gb";

    if (ram === 0 || specs.ram === "Unlimited")
      productId = "panel-premium";
    else if (ram == 1500) productId = "panel-1gb";
    else if (ram == 3500) productId = "panel-2gb";
    else if (ram == 4000) productId = "panel-3gb";
    else if (ram == 5000) productId = "panel-4gb";
    else if (ram == 6000) productId = "panel-5gb";
    else if (ram == 7000) productId = "panel-6gb";
    else if (ram == 8000) productId = "panel-7gb";

    const settings = await loadSettings();
    const priceMap = settings.PRICES || config.PRICES;

    let basePrice = 3000;

    if (productId === "panel-1gb") basePrice = priceMap.PANEL_1GB || 3000;
    else if (productId === "panel-2gb") basePrice = priceMap.PANEL_2GB || 5000;
    else if (productId === "panel-3gb") basePrice = priceMap.PANEL_3GB || 7000;
    else if (productId === "panel-4gb") basePrice = priceMap.PANEL_4GB || 9000;
    else if (productId === "panel-5gb") basePrice = priceMap.PANEL_5GB || 11000;
    else if (productId === "panel-6gb") basePrice = priceMap.PANEL_6GB || 14000;
    else if (productId === "panel-7gb") basePrice = priceMap.PANEL_7GB || 18000;
    else if (productId === "panel-premium") basePrice = priceMap.PANEL_PREMIUM || 30000;

    orderData.basePrice = basePrice;

    let currentExpire = new Date(server.panel_data.expires_at).getTime();
    if (currentExpire < Date.now()) currentExpire = Date.now();

    const addDays = parseInt(orderData.days) || 30;
    const newExpire = currentExpire + addDays * 86400000;

    server.panel_data.expires_at = new Date(newExpire).toISOString();
    server.days = (parseInt(server.days) || 0) + addDays;

    delete server.suspend_by;

    db[serverIndex] = server;
    await saveServerDatabase(db);

    try {
      await axios.post(
        `${config.PTERODACTYL.DOMAIN}/api/application/servers/${orderData.server_id}/unsuspend`,
        {},
        {
          headers: {
            Authorization: `Bearer ${config.PTERODACTYL.API_KEY}`,
            Accept: "application/json"
          }
        }
      );
    } catch (e) {}

    return {
      success: true,
      message: "Server berhasil diperpanjang",
      username: server.username,
      server_id: orderData.server_id,
      new_expiry: server.panel_data.expires_at,
      added_days: addDays,
      total_days: server.days,
      product_id: productId
    };

  } catch (error) {
    throw new Error(`Gagal memperpanjang server: ${error.message}`);
  }
}

app.post('/api/renew-panel', async (req, res) => {
  try {
    const { username, days } = req.body;

    if (!username || !days) {
      return res.status(400).json({ 
        success: false,
        error: 'Username dan days diperlukan' 
      });
    }

    const db = await loadServerDatabase();
    const server = db.find(panel => 
      panel.username === username || 
      (panel.panel_data && panel.panel_data.username === username)
    );

    if (!server) {
      return res.status(404).json({
        success: false,
        error: 'Server tidak ditemukan'
      });
    }

    let productId = 'panel-1gb';
    let productDisplayName = 'NODE 1GB';
    const specs = server.panel_data.specs || {};
    const ram = specs.ram_raw || specs.ram;

    if (ram === 0 || specs.ram === 'Unlimited' || server.product_name.includes('Unlimited')) {
      productId = 'panel-premium';
      productDisplayName = 'NODE UNLIMITED';
    } else if (ram === 1500 || ram === '1500' || specs.ram === '1.5GB') {
      productId = 'panel-1gb';
      productDisplayName = 'NODE 1GB';
    } else if (ram === 3500 || ram === '3500' || specs.ram === '3.5GB') {
      productId = 'panel-2gb';
      productDisplayName = 'NODE 2GB';
    } else if (ram === 4000 || ram === '4000' || specs.ram === '4GB') {
      productId = 'panel-3gb';
      productDisplayName = 'NODE 3GB';
    } else if (ram === 5000 || ram === '5000') {
      productId = 'panel-4gb';
      productDisplayName = 'NODE 4GB';
    } else if (ram === 6000 || ram === '6000' || specs.ram === '6GB') {
      productId = 'panel-5gb';
      productDisplayName = 'NODE 5GB';
    } else if (ram === 7000 || ram === '7000') {
      productId = 'panel-6gb';
      productDisplayName = 'NODE 6GB';
    } else if (ram === 8000 || ram === '8000' || specs.ram === '8GB') {
      productId = 'panel-7gb';
      productDisplayName = 'NODE 7GB';
    }

    const settings = await loadSettings();
    const priceMap = settings.PRICES || config.PRICES;

    let basePrice = 3000;
    if (productId === 'panel-1gb') basePrice = priceMap.PANEL_1GB || 3000;
    else if (productId === 'panel-2gb') basePrice = priceMap.PANEL_2GB || 5000;
    else if (productId === 'panel-3gb') basePrice = priceMap.PANEL_3GB || 7000;
    else if (productId === 'panel-4gb') basePrice = priceMap.PANEL_4GB || 9000;
    else if (productId === 'panel-5gb') basePrice = priceMap.PANEL_5GB || 11000;
    else if (productId === 'panel-6gb') basePrice = priceMap.PANEL_6GB || 14000;
    else if (productId === 'panel-7gb') basePrice = priceMap.PANEL_7GB || 18000;
    else if (productId === 'panel-premium') basePrice = priceMap.PANEL_PREMIUM || 30000;

    const calculatedPrice = Math.ceil((basePrice / 30) * parseInt(days));

    res.json({
      success: true,
      product_id: productId,
      product_name: productDisplayName,
      original_product_name: server.product_name,
      base_price: basePrice,
      calculated_price: calculatedPrice,
      days: parseInt(days),
      server_id: server.panel_data.server_id,
      server_name: server.panel_data.server_name,
      specs: specs,
      note: `Rp ${basePrice.toLocaleString()} / 30 hari (Rp ${Math.ceil(basePrice/30).toLocaleString()} per hari)`
    });

  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

app.get('/', async (req, res) => {
  try {
    const settings = await loadSettings();

    if (settings.MAINTENANCE_MODE) {
      return res.render('maintenance', { 
        storeName: config.STORE_NAME,
        message: settings.ANNOUNCEMENT?.text || 'Website sedang dalam pemeliharaan. Silakan kembali lagi nanti.'
      });
    }
    const viewConfig = {
      CHANNEL_LINK: config.CHANNEL_LINK,
      BOT_GROUP_LINK: config.BOT_GROUP_LINK,
      STORE_GROUP_LINK: config.STORE_GROUP_LINK,
      CONTACT_ADMIN: config.CONTACT_ADMIN,
      CONTACT_WHATSAPP: config.CONTACT_WHATSAPP,
      WEBSITE_LOGO: settings.WEBSITE_LOGO || config.WEBSITE_LOGO,
      WEBSITE_BANNER: settings.WEBSITE_BANNER || config.WEBSITE_BANNER
    };

    res.render('index', {
      storeName: config.STORE_NAME,
      announcement: settings.ANNOUNCEMENT || { text: '', active: false },
      restock: settings.RESTOCK || false,
      otherProducts: settings.OTHER_PRODUCTS || [],
      config: viewConfig 
    });
  } catch (error) {
    const viewConfig = {
      CHANNEL_LINK: config.CHANNEL_LINK,
      BOT_GROUP_LINK: config.BOT_GROUP_LINK,
      STORE_GROUP_LINK: config.STORE_GROUP_LINK,
      CONTACT_ADMIN: config.CONTACT_ADMIN,
      CONTACT_WHATSAPP: config.CONTACT_WHATSAPP
    };

    res.render('index', {
      storeName: config.STORE_NAME,
      announcement: { text: '', active: false },
      restock: false,
      otherProducts: [],
      config: viewConfig
    });
  }
});

app.listen(PORT, () => {
  console.log(`${config.STORE_NAME} running on port ${PORT}`);
  console.log(`http://localhost:${PORT}`);
});

module.exports = app;