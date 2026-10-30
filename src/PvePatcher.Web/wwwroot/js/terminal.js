// Terminal SSH da UI: instâncias do xterm.js (vendorizado em lib/xterm) ligadas ao WebSocket /terminal/ws.
// O Blazor cuida das abas; este módulo cuida do terminal, das preferências (localStorage) e dos uploads (XHR com progresso).

const PREFS_KEY = 'pve-patcher.terminal.prefs';
const DEFAULT_PREFS = {
    fontFamily: 'ui-monospace, "Cascadia Mono", "DejaVu Sans Mono", Menlo, Consolas, monospace',
    fontSize: 14,
    theme: 'dark',
    scrollback: 5000,
    cursorBlink: true,
    copyOnSelect: true,     // PuTTY: selecionar já copia
    rightClickPaste: true,  // PuTTY: botão direito cola
};

const THEMES = {
    dark: { background: '#0f1218', foreground: '#d8dee9', cursor: '#d8dee9', selectionBackground: '#3b4252' },
    light: {
        background: '#fbfbfb', foreground: '#1c2330', cursor: '#1c2330', selectionBackground: '#c8d4ef',
        black: '#1c2330', red: '#b4232a', green: '#1f7a3d', yellow: '#8a6d00', blue: '#2f6feb', magenta: '#7a1fa2', cyan: '#0e7490', white: '#d0d4dc',
        brightBlack: '#667085', brightRed: '#d1343c', brightGreen: '#2b9a52', brightYellow: '#a98600', brightBlue: '#4d86f0', brightMagenta: '#9a3ec2', brightCyan: '#1593b3', brightWhite: '#ffffff',
    },
    solarized: {
        background: '#002b36', foreground: '#839496', cursor: '#93a1a1', selectionBackground: '#073642',
        black: '#073642', red: '#dc322f', green: '#859900', yellow: '#b58900', blue: '#268bd2', magenta: '#d33682', cyan: '#2aa198', white: '#eee8d5',
        brightBlack: '#586e75', brightRed: '#cb4b16', brightGreen: '#93a1a1', brightYellow: '#657b83', brightBlue: '#839496', brightMagenta: '#6c71c4', brightCyan: '#93a1a1', brightWhite: '#fdf6e3',
    },
};

const terms = new Map();
let prefs = loadPrefs();
let libs;

function loadScript(src) {
    return new Promise((resolve, reject) => {
        const s = document.createElement('script');
        s.src = src;
        s.onload = resolve;
        s.onerror = () => reject(new Error('falha ao carregar ' + src));
        document.head.appendChild(s);
    });
}

function ensureLibs() {
    libs ??= (async () => {
        if (!document.querySelector('link[data-xterm]')) {
            // O fit mede as células com o CSS do xterm aplicado: espera ele carregar.
            await new Promise(resolve => {
                const l = document.createElement('link');
                l.rel = 'stylesheet';
                l.href = 'lib/xterm/xterm.css';
                l.dataset.xterm = '1';
                l.onload = l.onerror = resolve;
                document.head.appendChild(l);
            });
        }
        await loadScript('lib/xterm/xterm.js');
        await loadScript('lib/xterm/addon-fit.js');
        await loadScript('lib/xterm/addon-web-links.js');
    })();
    return libs;
}

function loadPrefs() {
    try {
        const raw = localStorage.getItem(PREFS_KEY);
        return { ...DEFAULT_PREFS, ...(raw ? JSON.parse(raw) : {}) };
    } catch {
        return { ...DEFAULT_PREFS };
    }
}

function options(p) {
    return {
        fontFamily: p.fontFamily,
        fontSize: Number(p.fontSize) || DEFAULT_PREFS.fontSize,
        scrollback: Number(p.scrollback) || DEFAULT_PREFS.scrollback,
        cursorBlink: !!p.cursorBlink,
        theme: THEMES[p.theme] ?? THEMES.dark,
    };
}

export async function init() {
    await ensureLibs();
    return prefs;
}

export function getDefaults() {
    return { ...DEFAULT_PREFS };
}

export function setPrefs(p) {
    prefs = { ...DEFAULT_PREFS, ...p };
    try { localStorage.setItem(PREFS_KEY, JSON.stringify(prefs)); } catch { /* sem storage: vale só nesta página */ }
    for (const t of terms.values()) {
        Object.assign(t.term.options, options(prefs));
        t.el.style.background = options(prefs).theme.background;
        t.fit.fit();
    }
}

async function copy(text) {
    if (!text) return;
    try { await navigator.clipboard.writeText(text); } catch { /* sem permissão ou sem HTTPS */ }
}

async function paste(t) {
    try {
        const text = await navigator.clipboard.readText();
        if (text) t.term.paste(text);
    } catch { /* sem permissão ou sem HTTPS */ }
}

/** Abre um terminal no elemento e conecta. vmQuery = "vm=cluster/vmid". */
export async function open(id, el, vmQuery, dotnet) {
    await ensureLibs();
    close(id);

    const term = new Terminal({ ...options(prefs), allowProposedApi: false, convertEol: false });
    el.style.background = options(prefs).theme.background; // a margem do host acompanha o tema
    const fit = new FitAddon.FitAddon();
    term.loadAddon(fit);
    term.loadAddon(new WebLinksAddon.WebLinksAddon());
    term.open(el);
    try { fit.fit(); } catch { /* elemento oculto */ }

    const url = new URL(`terminal/ws?${vmQuery}&cols=${term.cols}&rows=${term.rows}`, document.baseURI);
    url.protocol = url.protocol === 'https:' ? 'wss:' : 'ws:';
    const ws = new WebSocket(url);
    ws.binaryType = 'arraybuffer';
    const enc = new TextEncoder();
    const t = { term, fit, ws, el, dotnet, failed: false, ro: null };
    terms.set(id, t);

    const status = (s, msg) => dotnet.invokeMethodAsync('OnStatus', id, s, msg ?? null).catch(() => { });
    term.write('\x1b[90mConectando...\x1b[0m\r\n');

    ws.onopen = () => { t.opened = true; status('connected'); };
    ws.onmessage = ev => {
        if (typeof ev.data !== 'string') {
            term.write(new Uint8Array(ev.data));
            return;
        }
        let m;
        try { m = JSON.parse(ev.data); } catch { return; }
        if (m.t === 'error') {
            t.failed = true;
            term.write(`\r\n\x1b[31m${m.m}\x1b[0m\r\n`);
            status('error', m.m);
        }
    };
    ws.onclose = () => {
        if (terms.get(id) !== t) return;
        if (!t.opened && !t.failed) {
            // O navegador não diz por que o handshake falhou: as causas comuns são estas.
            t.failed = true;
            const msg = 'Não foi possível abrir a conexão do terminal. A sessão do app pode ter expirado (o serviço reiniciou?): recarregue a página. Atrás de proxy, confira o suporte a WebSocket em /terminal/ws.';
            term.write(`\r\n\x1b[31m${msg}\x1b[0m\r\n`);
            status('error', msg);
            return;
        }
        if (!t.failed) {
            term.write('\r\n\x1b[90m[sessão encerrada]\x1b[0m\r\n');
            status('closed');
        }
    };

    const send = data => { if (ws.readyState === WebSocket.OPEN) ws.send(data); };
    term.onData(d => send(enc.encode(d)));
    term.onBinary(d => send(Uint8Array.from(d, c => c.charCodeAt(0) & 0xff)));
    term.onResize(({ cols, rows }) => send(JSON.stringify({ t: 'resize', c: cols, r: rows })));
    term.onSelectionChange(() => { if (prefs.copyOnSelect && term.hasSelection()) copy(term.getSelection()); });

    term.attachCustomKeyEventHandler(e => {
        if (e.type !== 'keydown') return true;
        if (e.ctrlKey && e.shiftKey && e.code === 'KeyC') { copy(term.getSelection()); return false; }
        if (e.ctrlKey && e.shiftKey && e.code === 'KeyV') { paste(t); return false; }
        if (e.shiftKey && e.code === 'Insert') { paste(t); return false; }
        if (e.ctrlKey && e.code === 'Insert') { copy(term.getSelection()); return false; }
        return true;
    });
    t.onContext = e => {
        if (!prefs.rightClickPaste) return;
        e.preventDefault();
        paste(t);
    };
    el.addEventListener('contextmenu', t.onContext);

    let pending = 0;
    t.ro = new ResizeObserver(() => {
        cancelAnimationFrame(pending);
        pending = requestAnimationFrame(() => {
            if (el.offsetParent === null) return; // aba oculta
            try { fit.fit(); } catch { /* ignora */ }
        });
    });
    t.ro.observe(el);
    term.focus();
}

export function fit(id) {
    const t = terms.get(id);
    if (!t) return;
    try { t.fit.fit(); } catch { /* ignora */ }
    t.term.focus();
}

export function close(id) {
    const t = terms.get(id);
    if (!t) return;
    terms.delete(id);
    try { t.ws.close(); } catch { /* ignora */ }
    t.ro?.disconnect();
    t.el.removeEventListener('contextmenu', t.onContext);
    t.term.dispose();
}

export function closeAll() {
    for (const id of [...terms.keys()]) close(id);
}

/** Envia os arquivos escolhidos no input para a pasta via POST multipart, um por vez, com progresso. */
export async function upload(id, input, vmQuery, dir, overwrite, dotnet) {
    const files = [...(input.files ?? [])];
    input.value = '';
    for (const file of files) {
        const err = await new Promise(resolve => {
            const xhr = new XMLHttpRequest();
            const url = new URL(`terminal/sftp/upload?${vmQuery}&dir=${encodeURIComponent(dir)}&overwrite=${overwrite ? 'true' : 'false'}`, document.baseURI);
            xhr.open('POST', url);
            xhr.upload.onprogress = e => {
                if (e.lengthComputable) dotnet.invokeMethodAsync('OnUploadProgress', id, file.name, Math.round(e.loaded * 100 / e.total)).catch(() => { });
            };
            xhr.onload = () => resolve(xhr.status >= 200 && xhr.status < 300 ? null : (xhr.responseText || `HTTP ${xhr.status}`));
            xhr.onerror = () => resolve('falha de rede');
            const fd = new FormData();
            fd.append('file', file, file.name);
            xhr.send(fd);
        });
        await dotnet.invokeMethodAsync('OnUploadDone', id, file.name, err).catch(() => { });
        if (err) break;
    }
}
