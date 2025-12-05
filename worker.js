import { connect } from 'cloudflare:sockets';

let subPath = 'link';
let proxyIP = '13.230.34.30';
let password = '5dc15e15-f285-4a9d-959b-0e4fbdd77b88';
let SSpath = '';
let cfip = [
    'mfa.gov.ua#SG', 'saas.sin.fan#JP', 'store.ubi.com#SG','cf.130519.xyz#KR','cf.008500.xyz#HK', 
    'cf.090227.xyz#SG', 'cf.877774.xyz#HK','cdns.doon.eu.org#JP','sub.danfeng.eu.org#TW','cf.zhetengsha.eu.org#HK'
];
const concurrency = 4; //并发连接数 snippets请设置为1
const bufferSize = 512 * 1024;
const flushTime = 3;
const wsUserBufferer = true;
const dohEndpoints = ['https://cloudflare-dns.com/dns-query', 'https://dns.google/dns-query'];

const splitList = (raw) => raw
    .split(/[\n,]+/)
    .map(s => s.trim())
    .filter(Boolean);
const safeDecode = (value) => {
    if (!value) return value;
    try { return decodeURIComponent(value); }
    catch { return value; }
};
const getUniqueName = (base, used) => {
    let name = base;
    let counter = 1;
    while (used.has(name)) {
        counter += 1;
        name = `${base}-${counter}`;
    }
    used.add(name);
    return name;
};
function parseHostEntry(entry) {
    if (!entry) return null;
    let value = entry;
    let name = '';
    if (entry.includes('#')) {
        const parts = entry.split('#');
        value = parts.shift();
        name = parts.join('#');
    }
    let host = value;
    let port = 443;
    if (value.startsWith('[') && value.includes(']:')) {
        const idx = value.indexOf(']:');
        host = value.substring(0, idx + 1);
        port = parseInt(value.substring(idx + 2), 10) || 443;
    } else if (value.includes(':')) {
        const parts = value.split(':');
        host = parts[0];
        port = parseInt(parts[1], 10) || 443;
    }
    const plainHost = host.startsWith('[') && host.endsWith(']') ? host.slice(1, -1) : host;
    return {raw: entry, host, port, name, plainHost};
}

function extractNodeName(node, fallback) {
    const idx = node.indexOf('#');
    if (idx === -1) return fallback;
    const tail = node.substring(idx + 1);
    try { return decodeURIComponent(tail) || fallback; }
    catch { return tail || fallback; }
}

function attachNodeName(node, name) {
    const base = node.split('#')[0];
    if (!name) return base;
    return `${base}#${encodeURIComponent(name)}`;
}

function replaceEndpoint(node, host, port) {
    try {
        const url = new URL(node);
        url.hostname = host;
        if (port) url.port = port.toString();
        else url.port = '';
        return url.toString();
    } catch {
        return null;
    }
}

function buildCustomPreferredNodes(customNodes, cfEntries) {
    const results = [];
    customNodes.forEach((node, idx) => {
        const baseName = extractNodeName(node, `自定义-${idx + 1}`);
        cfEntries.forEach(entry => {
            const updated = replaceEndpoint(node, entry.plainHost, entry.port);
            if (!updated) return;
            const tag = entry.name || entry.plainHost;
            const finalName = `${baseName}-${tag}`;
            results.push(attachNodeName(updated, finalName));
        });
    });
    return results;
}

const CONFIG_KV_KEY = 'SS_CONFIG_STATE';
const yamlQuote = (s) => `"${(s || '').replace(/\\/g, '\\\\').replace(/"/g, '\\"')}"`;

function parseCustomNode(uri, fallbackName) {
    if (!uri) return null;
    try {
        const url = new URL(uri);
        const protocol = url.protocol.replace(':', '').toLowerCase();
        const name = extractNodeName(uri, fallbackName);
        if (protocol === 'vless') {
            const params = url.searchParams;
            const uuid = safeDecode(url.username || '');
            if (!uuid) return null;
            const port = parseInt(url.port, 10) || 443;
            const security = (params.get('security') || '').toLowerCase();
            const network = (params.get('type') || params.get('network') || 'tcp').toLowerCase();
            const path = params.get('path') ? safeDecode(params.get('path')) : '/';
            const hostHeader = safeDecode(params.get('host') || params.get('authority') || '');
            const flow = params.get('flow') || '';
            const fp = params.get('fp') || params.get('client-fingerprint') || '';
            const alpn = params.get('alpn') || '';
            const sni = safeDecode(params.get('sni') || '');
            const pbk = params.get('pbk') || '';
            const sid = params.get('sid') || params.get('short-id') || params.get('shortId') || '';
            const spx = params.get('spx') || '';
            const udp = params.get('udp') !== '0';
            return {
                type: 'vless',
                name,
                server: url.hostname,
                port,
                uuid,
                security,
                tls: security === 'tls' || security === 'reality',
                network,
                path,
                hostHeader,
                flow,
                fingerprint: fp,
                alpn,
                sni,
                pbk,
                sid,
                spx,
                udp
            };
        }
    } catch (e) {}
    return null;
}

function buildVlessProxyYaml(node) {
    const name = yamlQuote(node.name);
    let line = `  - {name: ${name}, type: vless, server: ${yamlQuote(node.server)}, port: ${node.port}, uuid: "${node.uuid}", udp: ${node.udp ? 'true' : 'false'}, network: ${node.network}, tls: ${node.tls ? 'true' : 'false'}`;
    if (node.security === 'reality') {
        const realityOpts = [];
        if (node.pbk) realityOpts.push(`public-key: "${node.pbk}"`);
        if (node.sid) realityOpts.push(`short-id: "${node.sid}"`);
        if (node.spx) realityOpts.push(`spider-x: "${node.spx}"`);
        if (realityOpts.length) line += `, reality-opts: {${realityOpts.join(', ')}}`;
        if (node.sni) line += `, servername: ${yamlQuote(node.sni)}`;
    } else if (node.sni) {
        line += `, servername: ${yamlQuote(node.sni)}`;
    }
    if (node.fingerprint) line += `, "client-fingerprint": ${yamlQuote(node.fingerprint)}`;
    if (node.flow) line += `, flow: ${node.flow}`;
    if (node.alpn) {
        const alpns = node.alpn.split(',').map(s => s.trim()).filter(Boolean);
        if (alpns.length) line += `, alpn: [${alpns.map(a => yamlQuote(a)).join(', ')}]`;
    }
    if (node.network === 'ws') {
        const headerValue = node.hostHeader || node.sni || node.server;
        const headers = headerValue ? `, headers: {Host: ${yamlQuote(headerValue)}}` : '';
        line += `, "ws-opts": {path: ${yamlQuote(node.path || '/')}${headers}}`;
    }
    line += '}';
    return line;
}

async function loadConfig(env) {
    const fallback = {cfip: [...cfip], custom: []};
    if (!env || !env.CONFIG_KV) return fallback;
    try {
        const stored = await env.CONFIG_KV.get(CONFIG_KV_KEY, {type: 'json'});
        if (stored && Array.isArray(stored.cfip) && stored.cfip.length) fallback.cfip = stored.cfip;
        if (stored && Array.isArray(stored.custom)) fallback.custom = stored.custom;
    } catch (e) {}
    return fallback;
}

async function saveConfig(env, cfList, customList) {
    if (!env || !env.CONFIG_KV) return false;
    try {
        await env.CONFIG_KV.put(CONFIG_KV_KEY, JSON.stringify({cfip: cfList, custom: customList}));
        return true;
    } catch (e) {
        return false;
    }
}

function escapeHtml(str) {
    return str.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}

function closeSocketQuietly(s) { 
    try { 
        if (s.readyState === WebSocket.OPEN || s.readyState === WebSocket.CLOSING) s.close();
    } catch {} 
}

function base64ToArray(s) {
    if (!s) return { error: null };
    try { 
        const b = atob(s.replace(/-/g, '+').replace(/_/g, '/'));
        const a = new Uint8Array(b.length);
        for (let i = 0; i < b.length; i++) a[i] = b.charCodeAt(i);
        return { earlyData: a.buffer, error: null }; 
    } catch (e) { 
        return { error: e }; 
    }
}

function parsePryAddress(s) {
    if (!s) return null;
    s = s.trim();
    if (s.startsWith('socks://') || s.startsWith('socks5://')) {
        try {
            const u = new URL(s.replace(/^socks:\/\//, 'socks5://'));
            return {type: 'socks5', host: u.hostname, port: parseInt(u.port) || 1080, username: u.username ? decodeURIComponent(u.username) : '', password: u.password ? decodeURIComponent(u.password) : ''};
        } catch {return null}
    }
    if (s.startsWith('http://') || s.startsWith('https://')) {
        try {
            const u = new URL(s);
            return {type: 'http', host: u.hostname, port: parseInt(u.port) || (s.startsWith('https://') ? 443 : 80), username: u.username ? decodeURIComponent(u.username) : '', password: u.password ? decodeURIComponent(u.password) : ''};
        } catch {return null}
    }
    if (s.startsWith('[')) {
        const i = s.indexOf(']');
        if (i > 0) {
            const h = s.substring(1, i);
            const r = s.substring(i + 1);
            if (r.startsWith(':')) {
                const p = parseInt(r.substring(1), 10);
                if (!isNaN(p) && p > 0 && p <= 65535) return {type: 'direct', host: h, port: p};
            }
            return {type: 'direct', host: h, port: 443};
        }
    }
    const i = s.lastIndexOf(':');
    if (i > 0) {
        const h = s.substring(0, i);
        const p = parseInt(s.substring(i + 1), 10);
        if (!isNaN(p) && p > 0 && p <= 65535) return {type: 'direct', host: h, port: p};
    }
    return {type: 'direct', host: s, port: 443};
}

function isSpeedTestSite(h) {
    const d = ['speedtest.net','fast.com','speedtest.cn','speed.cloudflare.com', 'ovo.speedtestcustom.com'];
    return d.some(x => h === x || h.endsWith('.' + x));
}

const isIPv4 = (str) => {
    if (str.length > 15 || str.length < 7) return false;
    let part = 0, dots = 0, partLen = 0;
    for (let i = 0; i < str.length; i++) {
        const c = str.charCodeAt(i);
        if (c === 46) {
            if (++dots > 3 || partLen === 0 || (str.charCodeAt(i - 1) === 48 && partLen > 1)) return false;
            part = 0; partLen = 0;
        } else if (c >= 48 && c <= 57) {
            part = part * 10 + (c - 48);
            if (++partLen > 3 || part > 255) return false;
        } else return false;
    }
    return dots === 3 && partLen > 0 && !(str.charCodeAt(str.length - partLen) === 48 && partLen > 1);
};

const isDomain = (str) => str && str[0] !== '[' && (str[0].charCodeAt(0) < 48 || str[0].charCodeAt(0) > 57 || !isIPv4(str));

const createConnect = (hostname, port) => {
    const socket = connect({hostname, port});
    return socket.opened.then(() => socket);
};

const concurrentConnect = (hostname, port) => {
    if (!isDomain(hostname)) return createConnect(hostname, port);
    return Promise.any(Array(concurrency).fill(null).map(() => createConnect(hostname, port)));
};

const calculateBuffer = (speed) => {
    if (speed === 0) return {size: bufferSize, time: flushTime};
    const bps = speed * 1048576;
    const init = (bps * 100) / 1000;
    let time = init < 20480 ? Math.ceil((20480 * 1000) / bps) : init > 4194304 ? Math.ceil((4194304 * 1000) / bps) : 100;
    if (time > 100) time = 100;
    let size = Math.ceil(((bps * time) / 1000) / 4096) * 4096;
    if (size > 4194304) size = 4194304;
    return {size, time};
};

const dohDns = async (payload) => {
    if (payload.byteLength < 2) throw new Error();
    const query = payload.subarray(2);
    const resp = await Promise.any(dohEndpoints.map(ep =>
        fetch(ep, {method: 'POST', headers: {'content-type': 'application/dns-message'}, body: query}).then(r => {
            if (!r.ok) throw new Error();
            return r;
        })
    ));
    const result = await resp.arrayBuffer();
    const size = result.byteLength;
    const packet = new Uint8Array(2 + size);
    packet[0] = (size >> 8) & 0xff;
    packet[1] = size & 0xff;
    packet.set(new Uint8Array(result), 2);
    return packet;
};

export default {
    async fetch(request,env) {
        try {
            // if (env.PROXYIP) proxyIP = env.PROXYIP.split(',')[0].trim();
            // password = env.PASSWORD || env.uuid || password;
            // subPath = env.SUB_PATH || subPath;
            // SSpath = env.SSPATH || SSpath;

            if (subPath === 'link' || subPath === '') {
                subPath = password;
            }
            if (SSpath === '') {
                SSpath = password;
            }
            let validPath = `/${SSpath}`;
            const servers = proxyIP.split(',').map(s => s.trim());
            proxyIP = servers[0]; 

            const method = 'none';
            const url = new URL(request.url);
            const pathname = url.pathname;

            if (request.method === 'POST' && pathname === '/config') {
                const payload = await request.json().catch(() => null);
                if (!payload) return new Response(JSON.stringify({success: false, message: 'Invalid payload'}), {status: 400, headers: {'Content-Type': 'application/json'}});
                const newCf = splitList(payload.cfip || '');
                const cfList = newCf.length ? newCf : [...cfip];
                const customList = splitList(payload.custom || '');
                const saved = await saveConfig(env, cfList, customList);
                if (!saved) return new Response(JSON.stringify({success: false, message: 'KV存储不可用'}), {status: 500, headers: {'Content-Type': 'application/json'}});
                return new Response(JSON.stringify({success: true}), {status: 200, headers: {'Content-Type': 'application/json'}});
            }

            const config = await loadConfig(env);
            const cfEntries = (config.cfip || cfip).map(parseHostEntry).filter(Boolean);
            const customNodes = config.custom || [];
            const customPreferredNodes = buildCustomPreferredNodes(customNodes, cfEntries);
            const combinedCustomNodes = customNodes.concat(customPreferredNodes);
            
            let pathProxyIP = null;
            if (pathname.startsWith('/proxyip=')) {
                try {pathProxyIP = decodeURIComponent(pathname.substring(9)).trim();} catch {}
                if (pathProxyIP && !request.headers.get('Upgrade')) {
                    proxyIP = pathProxyIP;
                    return new Response(`set proxyIP to: ${proxyIP}\n\n`, {headers: {'Content-Type': 'text/plain; charset=utf-8'}});
                }
            }

            if (request.headers.get('Upgrade') === 'websocket') {
                if (!pathname.toLowerCase().startsWith(validPath.toLowerCase())) {
                    return new Response('Unauthorized', { status: 401 });
                }
                let wsPathProxyIP = null;
                if (pathname.startsWith('/proxyip=')) {
                    try {
                        wsPathProxyIP = decodeURIComponent(pathname.substring(9)).trim();
                    } catch (e) {}
                }
                const customProxyIP = wsPathProxyIP || url.searchParams.get('proxyip') || request.headers.get('proxyip');
                const speedParam = url.searchParams.get('speed');
                const speed = speedParam ? Math.max(0, parseInt(speedParam, 10)) : 0;
                const cache = url.searchParams.get('cache') === '1' || (speed > 0) || wsUserBufferer;
                const concurrent = url.searchParams.get('concurrent') || concurrency;
                return await handleSSRequest(request, customProxyIP, speed, cache, parseInt(concurrent));
            } else if (request.method === 'GET') {
                if (url.pathname === '/') {
                    return getSimplePage(request);
                }
                
                if (url.pathname.toLowerCase() === `/${password.toLowerCase()}`) {
                    return getHomePage(request, validPath, config);
                }
                
                // 订阅路径 /sub/UUID
                if (url.pathname.toLowerCase() === `/sub/${subPath.toLowerCase()}` || url.pathname.toLowerCase() === `/sub/${subPath.toLowerCase()}/`) {
                    const d = url.hostname, h = 's'+'s';
                    const ssLinks = cfEntries.map(entry => {
                        const cfg = btoa(`${method}:${password}@${entry.host}:${entry.port}`);
                        const plugin = btoa(JSON.stringify({tls: true, mux: false, mode: "websocket", allowInsecure: true, host: d, peer: d, path: validPath + '?ed=2560'})).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
                        const nodeName = entry.name ? `${entry.name}-${h}` : h;
                        return `${h}://${cfg}?v2ray-plugin=${plugin}#${nodeName}`;
                    });
                    const merged = ssLinks.concat(combinedCustomNodes);
                    return new Response(btoa(unescape(encodeURIComponent(merged.join('\n')))), {headers: {'Content-Type': 'text/plain; charset=utf-8'}});
                }
                
                // YAML 订阅路径 /yaml/UUID
                if (url.pathname.toLowerCase() === `/yaml/${subPath.toLowerCase()}` || url.pathname.toLowerCase() === `/yaml/${subPath.toLowerCase()}/`) {
                    const d = url.hostname, ps = [], ns = [];
                    const usedNames = new Set();
                    cfEntries.forEach((entry, i) => {
                        const host = entry.host.startsWith('[') && entry.host.endsWith(']') ? entry.host.slice(1, -1) : entry.host;
                        const baseName = entry.name ? `${entry.name}-SS-${i + 1}` : `SS-${i + 1}`;
                        const uniqueName = getUniqueName(baseName, usedNames);
                        ns.push(uniqueName);
                        ps.push(`  - {name: "${uniqueName}", type: ss, server: ${host}, port: ${entry.port}, cipher: ${method}, password: "${password}", plugin: v2ray-plugin, plugin-opts: {mode: websocket, tls: true, skip-cert-verify: true, host: ${d}, path: "${validPath}?ed=2560", mux: false}, udp: false}`);
                    });
                    const customProxyEntries = [];
                    const unsupported = [];
                    combinedCustomNodes.forEach((nodeStr, idx) => {
                        const parsed = parseCustomNode(nodeStr, `自定义-${idx + 1}`);
                        if (parsed) {
                            parsed.name = getUniqueName(parsed.name, usedNames);
                            ns.push(parsed.name);
                            customProxyEntries.push(buildVlessProxyYaml(parsed));
                        } else {
                            unsupported.push(`# ${nodeStr}`);
                        }
                    });
                    ps.push(...customProxyEntries);
                    let extra = '';
                    if (unsupported.length) {
                        extra = `\n# 以下节点暂未能自动转为订阅所需格式，请手动处理：\n${unsupported.join('\n')}\n`;
                    }
                    const quotedNsArr = ns.map(n => JSON.stringify(n));
                    const quotedNs = quotedNsArr.join(', ');
                    const selectExtras = quotedNsArr.length ? `, ${quotedNs}` : '';
                    const listOnly = quotedNsArr.length ? `[${quotedNs}]` : '[]';
                    const y = `port: 7890\nsocks-port: 7891\nallow-lan: false\nmode: Rule\nlog-level: info\nexternal-controller: 127.0.0.1:9090\nproxies:\n${ps.join('\n')}\nproxy-groups:\n  - {name: "🚀 节点选择", type: select, proxies: ["♻️ 自动选择", "🔰 故障转移", DIRECT${selectExtras}]}\n  - {name: "♻️ 自动选择", type: url-test, proxies: ${listOnly}, url: "http://www.gstatic.com/generate_204", interval: 300}\n  - {name: "🔰 故障转移", type: fallback, proxies: ${listOnly}, url: "http://www.gstatic.com/generate_204", interval: 300}\nrules:\n  - DOMAIN-SUFFIX,local,DIRECT\n  - IP-CIDR,127.0.0.0/8,DIRECT\n  - IP-CIDR,172.16.0.0/12,DIRECT\n  - IP-CIDR,192.168.0.0/16,DIRECT\n  - IP-CIDR,10.0.0.0/8,DIRECT\n  - GEOIP,CN,DIRECT\n  - MATCH,🚀 节点选择${extra}`;
                    return new Response(y, {headers: {'Content-Type': 'text/yaml; charset=utf-8', 'Content-Disposition': 'attachment; filename="config.yaml"'}});
                }
            }
            return new Response('Not Found', { status: 404 });
        } catch (err) {
            return new Response('Internal Server Error', { status: 500 });
        }
    },
};

async function handleSSRequest(request, customProxyIP, speed, cache, concurrent) {
    const wssPair = new WebSocketPair();
    const [clientSock, serverSock] = Object.values(wssPair);
    serverSock.accept();
    let remoteConnWrapper = { socket: null };
    let isDnsQuery = false;
    const earlyData = request.headers.get('sec-websocket-protocol') || '';
    const readable = makeReadableStr(serverSock, earlyData);

    let pt = setInterval(() => { try { if (serverSock.readyState === 1) serverSock.send(new Uint8Array([0])); } catch {} }, 25000);

    readable.pipeTo(new WritableStream({
        async write(chunk) {
            if (isDnsQuery) {
                serverSock.send(await dohDns(chunk));
                return;
            }
            if (remoteConnWrapper.socket) {
                const writer = remoteConnWrapper.socket.writable.getWriter();
                await writer.write(chunk);
                writer.releaseLock();
                return;
            }
            
            const { hasError, message, addressType, port, hostname, rawIndex } = parseSSPacketHeader(chunk);
            if (hasError) throw new Error(message);

            if (isSpeedTestSite(hostname)) throw new Error('Speedtest blocked');

            if (addressType === 2) { 
                if (port === 53) {
                    isDnsQuery = true;
                    serverSock.send(await dohDns(chunk.slice(rawIndex)));
                    return;
                }
                throw new Error('UDP not supported');
            }
            
            const rawData = chunk.slice(rawIndex);
            await forwardataTCP(hostname, port, rawData, serverSock, remoteConnWrapper, customProxyIP, speed, cache, concurrent);
        },
    })).catch(() => {}).finally(() => { if (pt) clearInterval(pt); });

    return new Response(null, { status: 101, webSocket: clientSock });
}

function parseSSPacketHeader(chunk) {
    if (chunk.byteLength < 7) return { hasError: true, message: 'Invalid data' };
    
    try {
        const view = new Uint8Array(chunk);
        const addressType = view[0];
        let addrIdx = 1, addrLen = 0, addrValIdx = addrIdx, hostname = '';
        
        switch (addressType) {
            case 1: // IPv4
                addrLen = 4; 
                hostname = new Uint8Array(chunk.slice(addrValIdx, addrValIdx + addrLen)).join('.'); 
                addrValIdx += addrLen;
                break;
            case 3: // Domain
                addrLen = view[addrIdx];
                addrValIdx += 1; 
                hostname = new TextDecoder().decode(chunk.slice(addrValIdx, addrValIdx + addrLen)); 
                addrValIdx += addrLen;
                break;
            case 4: // IPv6
                addrLen = 16; 
                const ipv6 = []; 
                const ipv6View = new DataView(chunk.slice(addrValIdx, addrValIdx + addrLen)); 
                for (let i = 0; i < 8; i++) ipv6.push(ipv6View.getUint16(i * 2).toString(16)); 
                hostname = ipv6.join(':'); 
                addrValIdx += addrLen;
                break;
            default: 
                return { hasError: true, message: `Invalid address type: ${addressType}` };
        }
        
        if (!hostname) return { hasError: true, message: `Invalid address: ${addressType}` };
        
        const port = new DataView(chunk.slice(addrValIdx, addrValIdx + 2)).getUint16(0);
        return { hasError: false, addressType, port, hostname, rawIndex: addrValIdx + 2 };
    } catch (e) {
        return { hasError: true, message: 'Failed to parse SS packet header' };
    }
}

async function connect2Socks5(proxyConfig, targetHost, targetPort, initialData) {
    const { host, port, username, password } = proxyConfig;
    const socket = await createConnect(host, port);
    const writer = socket.writable.getWriter();
    const reader = socket.readable.getReader();
    
    try {
        const authMethods = username && password ? 
            new Uint8Array([0x05, 0x02, 0x00, 0x02]) :
            new Uint8Array([0x05, 0x01, 0x00]); 
        
        await writer.write(authMethods);
        const methodResponse = await reader.read();
        if (methodResponse.done || methodResponse.value.byteLength < 2) {
            throw new Error('S5 method selection failed');
        }
        
        const selectedMethod = new Uint8Array(methodResponse.value)[1];
        if (selectedMethod === 0x02) {
            if (!username || !password) {
                throw new Error('S5 requires authentication');
            }
            const userBytes = new TextEncoder().encode(username);
            const passBytes = new TextEncoder().encode(password);
            const authPacket = new Uint8Array(3 + userBytes.length + passBytes.length);
            authPacket[0] = 0x01; 
            authPacket[1] = userBytes.length;
            authPacket.set(userBytes, 2);
            authPacket[2 + userBytes.length] = passBytes.length;
            authPacket.set(passBytes, 3 + userBytes.length);
            await writer.write(authPacket);
            const authResponse = await reader.read();
            if (authResponse.done || new Uint8Array(authResponse.value)[1] !== 0x00) {
                throw new Error('S5 authentication failed');
            }
        } else if (selectedMethod !== 0x00) {
            throw new Error(`S5 unsupported auth method: ${selectedMethod}`);
        }
        
        const hostBytes = new TextEncoder().encode(targetHost);
        const connectPacket = new Uint8Array(7 + hostBytes.length);
        connectPacket[0] = 0x05;
        connectPacket[1] = 0x01;
        connectPacket[2] = 0x00; 
        connectPacket[3] = 0x03; 
        connectPacket[4] = hostBytes.length;
        connectPacket.set(hostBytes, 5);
        new DataView(connectPacket.buffer).setUint16(5 + hostBytes.length, targetPort, false);
        await writer.write(connectPacket);
        const connectResponse = await reader.read();
        if (connectResponse.done || new Uint8Array(connectResponse.value)[1] !== 0x00) {
            throw new Error('S5 connection failed');
        }
        
        await writer.write(initialData);
        writer.releaseLock();
        reader.releaseLock();
        return socket;
    } catch (error) {
        writer.releaseLock();
        reader.releaseLock();
        throw error;
    }
}

async function connect2Http(proxyConfig, targetHost, targetPort, initialData) {
    const { host, port, username, password } = proxyConfig;
    const socket = await createConnect(host, port);
    const writer = socket.writable.getWriter();
    const reader = socket.readable.getReader();
    try {
        let connectRequest = `CONNECT ${targetHost}:${targetPort} HTTP/1.1\r\n`;
        connectRequest += `Host: ${targetHost}:${targetPort}\r\n`;
        
        if (username && password) {
            const auth = btoa(`${username}:${password}`);
            connectRequest += `Proxy-Authorization: Basic ${auth}\r\n`;
        }
        
        connectRequest += `User-Agent: Mozilla/5.0\r\n`;
        connectRequest += `Connection: keep-alive\r\n`;
        connectRequest += '\r\n';
        await writer.write(new TextEncoder().encode(connectRequest));
        let responseBuffer = new Uint8Array(0);
        let headerEndIndex = -1;
        let bytesRead = 0;
        const maxHeaderSize = 8192;
        
        while (headerEndIndex === -1 && bytesRead < maxHeaderSize) {
            const { done, value } = await reader.read();
            if (done) {
                throw new Error('Connection closed before receiving HTTP response');
            }
            const newBuffer = new Uint8Array(responseBuffer.length + value.length);
            newBuffer.set(responseBuffer);
            newBuffer.set(value, responseBuffer.length);
            responseBuffer = newBuffer;
            bytesRead = responseBuffer.length;
            
            for (let i = 0; i < responseBuffer.length - 3; i++) {
                if (responseBuffer[i] === 0x0d && responseBuffer[i + 1] === 0x0a &&
                    responseBuffer[i + 2] === 0x0d && responseBuffer[i + 3] === 0x0a) {
                    headerEndIndex = i + 4;
                    break;
                }
            }
        }
        
        if (headerEndIndex === -1) {
            throw new Error('Invalid HTTP response');
        }
        
        const headerText = new TextDecoder().decode(responseBuffer.slice(0, headerEndIndex));
        const statusLine = headerText.split('\r\n')[0];
        const statusMatch = statusLine.match(/HTTP\/\d\.\d\s+(\d+)/);
        
        if (!statusMatch) {
            throw new Error(`Invalid response: ${statusLine}`);
        }
        
        const statusCode = parseInt(statusMatch[1]);
        if (statusCode < 200 || statusCode >= 300) {
            throw new Error(`Connection failed: ${statusLine}`);
        }
        
        console.log('HTTP connection established for Shadowsocks');
        
        await writer.write(initialData);
        writer.releaseLock();
        reader.releaseLock();
        
        return socket;
    } catch (error) {
        try { 
            writer.releaseLock(); 
        } catch (e) {}
        try { 
            reader.releaseLock(); 
        } catch (e) {}
        try { 
            socket.close(); 
        } catch (e) {}
        throw error;
    }
}

async function forwardataTCP(host, portNum, rawData, ws, remoteConnWrapper, customProxyIP, speed, cache, concurrent) {
    async function connectDirect(address, port, data, conc) {
        const remoteSock = await (conc > 1 ? concurrentConnect(address, port) : createConnect(address, port));
        const writer = remoteSock.writable.getWriter();
        await writer.write(data);
        writer.releaseLock();
        return remoteSock;
    }
    
    let proxyConfig = null;
    let shouldUseProxy = false;
    if (customProxyIP) {
        proxyConfig = parsePryAddress(customProxyIP);
        if (proxyConfig && (proxyConfig.type === 'socks5' || proxyConfig.type === 'http' || proxyConfig.type === 'https')) {
            shouldUseProxy = true;
        } else if (!proxyConfig) {
            proxyConfig = parsePryAddress(proxyIP) || { type: 'direct', host: proxyIP, port: 443 };
        }
    } else {
        proxyConfig = parsePryAddress(proxyIP) || { type: 'direct', host: proxyIP, port: 443 };
        if (proxyConfig.type === 'socks5' || proxyConfig.type === 'http' || proxyConfig.type === 'https') {
            shouldUseProxy = true;
        }
    }
    
    async function connecttoPry() {
        let newSocket;
        if (proxyConfig.type === 'socks5') {
            newSocket = await connect2Socks5(proxyConfig, host, portNum, rawData);
        } else if (proxyConfig.type === 'http' || proxyConfig.type === 'https') {
            newSocket = await connect2Http(proxyConfig, host, portNum, rawData);
        } else {
            newSocket = await connectDirect(proxyConfig.host, proxyConfig.port, rawData, 1);
        }
        
        remoteConnWrapper.socket = newSocket;
        connectStreams(newSocket, ws, null, speed, cache);
    }
    
    if (shouldUseProxy) {
        try {
            await connecttoPry();
        } catch (err) {
            throw err;
        }
    } else {
        try {
            const initialSocket = await connectDirect(host, portNum, rawData, concurrent);
            remoteConnWrapper.socket = initialSocket;
            connectStreams(initialSocket, ws, connecttoPry, speed, cache);
        } catch (err) {
            await connecttoPry();
        }
    }
}

function makeReadableStr(socket, earlyDataHeader) {
    let cancelled = false;
    return new ReadableStream({
        start(controller) {
            socket.addEventListener('message', (event) => { 
                if (!cancelled) controller.enqueue(event.data); 
            });
            socket.addEventListener('close', () => { 
                if (!cancelled) { 
                    closeSocketQuietly(socket); 
                    controller.close(); 
                } 
            });
            socket.addEventListener('error', (err) => controller.error(err));
            const { earlyData, error } = base64ToArray(earlyDataHeader);
            if (error) controller.error(error); 
            else if (earlyData) controller.enqueue(earlyData);
        },
        cancel() { 
            cancelled = true; 
            closeSocketQuietly(socket); 
        }
    });
}

async function connectStreams(remoteSocket, webSocket, retryFunc, speed, cache) {
    let ka = setInterval(() => { try { if (webSocket.readyState === 1) webSocket.send(new Uint8Array([0])); } catch {} }, 30000);
    const stop = () => { if (ka) clearInterval(ka); };
    remoteSocket.closed.catch(() => {}).finally(() => { stop(); closeSocketQuietly(webSocket); });

    if (!cache) {
        let hasData = false;
        await remoteSocket.readable.pipeTo(new WritableStream({
            async write(chunk, controller) {
                hasData = true;
                if (webSocket.readyState !== 1) controller.error('ws closed');
                webSocket.send(chunk);
            },
            abort() { stop(); },
        })).catch(() => { stop(); closeSocketQuietly(webSocket); });
        if (!hasData && retryFunc) await retryFunc();
        return;
    }

    const {size, time} = calculateBuffer(speed);
    const safe = size - 4096;
    let buf = new Uint8Array(size), offset = 0, timer = null, resume = null, hasData = false;
    const flush = () => {
        if (offset > 0) {
            webSocket.send(buf.subarray(0, offset));
            buf = new Uint8Array(size);
            offset = 0;
        }
        if (timer) {clearTimeout(timer); timer = null;}
        if (resume) {resume(); resume = null;}
    };

    const reader = remoteSocket.readable.getReader();
    try {
        while (true) {
            const {done, value: chunk} = await reader.read();
            if (done) break;
            hasData = true;
            if (chunk.length < 4096) {
                flush();
                webSocket.send(chunk);
            } else {
                buf.set(chunk, offset);
                offset += chunk.length;
                if (!timer) timer = setTimeout(flush, time);
                if (offset > safe) await new Promise(resolve => resume = resolve);
            }
        }
    } finally {
        flush();
        stop();
        reader.releaseLock();
    }
    if (!hasData && retryFunc) await retryFunc();
}



function getHomePage(request, validPath, config) {
    const url = request.headers.get('Host');
    const b = `https://${url}`;
    const cfList = (config && Array.isArray(config.cfip) && config.cfip.length ? config.cfip : cfip);
    const customList = (config && Array.isArray(config.custom) ? config.custom : []);
    const cfDefault = escapeHtml(cfList.join('\n'));
    const customDefault = escapeHtml(customList.join('\n'));
    const html = `<!DOCTYPE html><html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0"><title>SS Service</title><style>*{margin:0;padding:0;box-sizing:border-box}body{font-family:sans-serif;background:linear-gradient(135deg,#7dd3ca,#a17ec4);min-height:100vh;display:flex;align-items:center;justify-content:center}.container{background:rgba(255,255,255,.95);border-radius:20px;padding:20px;max-width:780px;width:95%;text-align:center}.title{font-size:1.8rem;margin-bottom:10px;color:#2d3748}.info{background:#f7fafc;border-radius:10px;padding:15px;margin:15px 0;text-align:left}.item{display:flex;justify-content:space-between;padding:8px 0;border-bottom:1px solid #e2e8f0}.item:last-child{border-bottom:none}.label{font-weight:600;color:#4a5568}.value{color:#2d3748;font-family:monospace;background:#edf2f7;padding:3px 6px;border-radius:4px;font-size:.85rem;text-decoration:none;display:inline-block}.copy-link{cursor:pointer}.copy-link:hover{background:#e0e7ff}.note{background:#fff3cd;border-radius:8px;padding:10px;margin:15px 0;color:#856404;font-size:.85rem;text-align:left}.custom-box{margin-top:15px;text-align:left}.custom-box h2{font-size:1rem;margin-bottom:8px;color:#2d3748}.custom-area{width:100%;min-height:110px;border-radius:10px;border:1px solid #cbd5f5;padding:10px;font-size:.9rem;resize:vertical}.custom-tip{font-size:.8rem;color:#4a5568;margin-top:5px}.btns{display:flex;gap:10px;justify-content:center;margin:20px 0}.btn{padding:10px 20px;background:linear-gradient(135deg,#12cd9e,#a881d0);color:#fff;border:none;border-radius:8px;cursor:pointer}.btn:active{opacity:.85}@media (max-width:768px){body{padding:15px}.btns{flex-direction:column}.btn{width:100%}}</style></head><body><div class="container"><h1 class="title">Shadowsocks Service</h1><div class="info"><div class="item"><span class="label">HOST</span><span class="value">${url}</span></div><div class="item"><span class="label">UUID</span><span class="value">${subPath}</span></div><div class="item"><span class="label">SS订阅</span><a id="ssLink" class="value copy-link" href="#" data-base="${b}/sub/${subPath}">点击复制</a></div><div class="item"><span class="label">YAML订阅</span><a id="yamlLink" class="value copy-link" href="#" data-base="${b}/yaml/${subPath}">点击复制</a></div></div><div class="note">注意：v2rayN导入节点需手动补全参数，path为：${validPath}?ed=2560</div><div class="custom-box"><h2>优选域名 / IP（覆盖 cfip，默认用于SS+套壳）</h2><textarea id="cfipInput" class="custom-area" placeholder="每行一个优选入口，如：mfa.gov.ua:443#SG">${cfDefault}</textarea><div class="custom-tip">此列表会生成默认CF SS节点；同时作为自定义节点的“优选壳”来源。</div></div><div class="custom-box"><h2>自定义节点（原生 + 自动优选）</h2><textarea id="customNodes" class="custom-area" placeholder="每行一个节点，例如：vless://uuid@host:443?...#名称">${customDefault}</textarea><div class="custom-tip">原生节点直接追加；同时会用上方优选入口替换 IP:端口 生成“自定义优选节点”。</div></div><div class="btns"><button class="btn" onclick="saveConfig()">保存并生成链接</button></div></div><script>function handleCopy(event){event.preventDefault();const el=event.currentTarget;const url=el.dataset.base;navigator.clipboard.writeText(url).then(()=>alert('已复制!')).catch(()=>{const textarea=document.createElement('textarea');textarea.value=url;document.body.appendChild(textarea);textarea.select();document.execCommand('copy');document.body.removeChild(textarea);alert('已复制!');});}async function saveConfig(){const cf=document.getElementById('cfipInput').value;const custom=document.getElementById('customNodes').value;try{const resp=await fetch('/config',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({cfip:cf,custom})});if(!resp.ok) throw new Error();alert('已保存，订阅链接保持不变，刷新订阅即可生效');}catch(e){alert('保存失败，请稍后再试');}}document.addEventListener('DOMContentLoaded',()=>{document.querySelectorAll('.copy-link').forEach(el=>el.addEventListener('click',handleCopy));});</script></body></html>`;
    return new Response(html, {status: 200, headers: {'Content-Type': 'text/html;charset=utf-8'}});
}

function getSimplePage(request) {
    const url = request.headers.get('Host');
    const html = `<!DOCTYPE html><html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0"><title>SS Service</title><style>body{font-family:sans-serif;background:linear-gradient(135deg,#7dd3ca,#a17ec4);height:100vh;display:flex;align-items:center;justify-content:center;margin:0}.container{background:rgba(255,255,255,.95);border-radius:20px;padding:40px;max-width:600px;text-align:center}.title{font-size:2rem;margin-bottom:20px;color:#2d3748}.tip{color:#856404;font-size:1rem}.highlight{font-weight:bold;background:#fff;padding:2px 6px;border-radius:4px}</style></head><body><div class="container"><h1 class="title">Hello Shadowsocks!</h1><div class="tip">访问 <span class="highlight">https://${url}/你的UUID</span> 进入订阅中心</div></div></body></html>`;
    return new Response(html, {
        status: 200,
        headers: {
            'Content-Type': 'text/html;charset=utf-8',
            'Cache-Control': 'no-cache, no-store, must-revalidate',
        },
    });
}
