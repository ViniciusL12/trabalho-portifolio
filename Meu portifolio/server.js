const crypto = require("node:crypto");
const fs = require("node:fs");
const http = require("node:http");
const path = require("node:path");

const root = __dirname;
const privateDirectory = path.join(root, "private-data");
const messagesFile = path.join(privateDirectory, "messages.json");
const isProduction = process.env.NODE_ENV === "production";

function loadEnvironmentFile() {
    const file = path.join(root, ".env");
    if (!fs.existsSync(file)) return;

    for (const line of fs.readFileSync(file, "utf8").split(/\r?\n/)) {
        const match = line.match(/^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*?)\s*$/);
        if (!match || match[1] in process.env) continue;

        let value = match[2];
        if (
            (value.startsWith('"') && value.endsWith('"')) ||
            (value.startsWith("'") && value.endsWith("'"))
        ) {
            value = value.slice(1, -1);
        }

        process.env[match[1]] = value;
    }
}

loadEnvironmentFile();

const adminPassword = process.env.ADMIN_PASSWORD;
if (!adminPassword || adminPassword.length < 16) {
    throw new Error(
        "Configure ADMIN_PASSWORD com pelo menos 16 caracteres no arquivo .env."
    );
}

const passwordSalt = crypto.randomBytes(16);
const passwordHash = crypto.scryptSync(adminPassword, passwordSalt, 32);
const sessionLifetimeMs = 12 * 60 * 60 * 1000;
const sessions = new Map();
const rateLimits = new Map();
const publicFiles = new Set([
    "index.html",
    "style.css",
    "script.js",
    "admin.html",
    "admin.js",
    "foto.jpg"
]);
const contentTypes = {
    ".css": "text/css; charset=utf-8",
    ".html": "text/html; charset=utf-8",
    ".jpg": "image/jpeg",
    ".js": "text/javascript; charset=utf-8",
    ".svg": "image/svg+xml"
};
const maxRequestBytes = 12 * 1024;
const maxMessages = 2000;

function sendJson(response, status, data, extraHeaders = {}) {
    response.writeHead(status, {
        "Cache-Control": "no-store",
        "Content-Type": "application/json; charset=utf-8",
        ...extraHeaders
    });
    response.end(JSON.stringify(data));
}

function getClientKey(request, prefix) {
    return `${prefix}:${request.socket.remoteAddress || "unknown"}`;
}

function consumeRateLimit(key, limit, windowMs) {
    const now = Date.now();
    let entry = rateLimits.get(key);

    if (!entry || entry.resetAt <= now) {
        entry = { count: 0, resetAt: now + windowMs };
        rateLimits.set(key, entry);
    }

    if (entry.count >= limit) {
        return {
            allowed: false,
            retryAfter: Math.ceil((entry.resetAt - now) / 1000)
        };
    }

    entry.count += 1;
    return { allowed: true };
}

function readJson(request) {
    return new Promise((resolve, reject) => {
        let size = 0;
        let body = "";
        let finished = false;

        request.setEncoding("utf8");
        request.on("data", chunk => {
            if (finished) return;
            size += Buffer.byteLength(chunk);

            if (size > maxRequestBytes) {
                finished = true;
                reject(Object.assign(new Error("A solicitação excede o limite permitido."), {
                    status: 413
                }));
                request.resume();
                return;
            }

            body += chunk;
        });
        request.on("end", () => {
            if (finished) return;
            try {
                const data = JSON.parse(body);
                if (!data || typeof data !== "object" || Array.isArray(data)) {
                    throw new Error("O corpo da solicitação deve ser um objeto JSON.");
                }
                resolve(data);
            } catch {
                reject(Object.assign(new Error("O corpo da solicitação não contém JSON válido."), {
                    status: 400
                }));
            }
        });
        request.on("error", error => {
            if (finished) return;
            finished = true;
            reject(error);
        });
        request.on("aborted", () => {
            if (finished) return;
            finished = true;
            reject(new Error("A solicitação foi interrompida."));
        });
    });
}

function isSameOrigin(request) {
    const origin = request.headers.origin;
    if (!origin) return true;

    try {
        return new URL(origin).host === request.headers.host;
    } catch {
        return false;
    }
}

function readMessages() {
    try {
        const content = fs.readFileSync(messagesFile, "utf8");
        const messages = JSON.parse(content);
        if (!Array.isArray(messages)) {
            throw new Error("O arquivo de mensagens não contém uma lista.");
        }
        return messages;
    } catch (error) {
        if (error.code === "ENOENT") return [];
        throw error;
    }
}

function saveMessages(messages) {
    fs.mkdirSync(privateDirectory, { recursive: true, mode: 0o700 });
    const temporaryFile = `${messagesFile}.${process.pid}.tmp`;
    fs.writeFileSync(temporaryFile, JSON.stringify(messages, null, 2), {
        encoding: "utf8",
        mode: 0o600
    });
    fs.renameSync(temporaryFile, messagesFile);
}

function getSession(request) {
    const cookie = request.headers.cookie || "";
    const match = cookie.match(/(?:^|;\s*)portfolio_session=([a-f0-9]{64})(?:;|$)/);
    if (!match) return null;

    const session = sessions.get(match[1]);
    if (!session) return null;
    if (session.expiresAt <= Date.now()) {
        sessions.delete(match[1]);
        return null;
    }

    return { token: match[1], session };
}

function requireSession(request, response) {
    const session = getSession(request);
    if (!session) {
        sendJson(response, 401, { message: "Faça login para acessar as mensagens." });
        return null;
    }
    return session;
}

function requireJson(request, response) {
    if (!request.headers["content-type"]?.toLowerCase().startsWith("application/json")) {
        sendJson(response, 415, { message: "Envie os dados no formato JSON." });
        return false;
    }
    return true;
}

function securityHeaders(response) {
    response.setHeader("X-Content-Type-Options", "nosniff");
    response.setHeader("Referrer-Policy", "strict-origin-when-cross-origin");
    response.setHeader("X-Frame-Options", "DENY");
    response.setHeader(
        "Content-Security-Policy",
        "default-src 'self'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'; object-src 'none'; img-src 'self' data:; style-src 'self'; script-src 'self'; connect-src 'self'"
    );
}

function servePublicFile(request, response, pathname) {
    const requestedName = pathname === "/" ? "index.html" :
        pathname === "/admin" ? "admin.html" :
            pathname.replace(/^\/+/, "");

    if (!publicFiles.has(requestedName)) {
        sendJson(response, 404, { message: "Página não encontrada." });
        return;
    }

    const file = path.join(root, requestedName);
    let content;
    try {
        content = fs.readFileSync(file);
    } catch (error) {
        if (error.code === "ENOENT") {
            sendJson(response, 404, { message: "Arquivo não encontrado." });
            return;
        }
        throw error;
    }

    response.writeHead(200, {
        "Cache-Control": requestedName === "admin.html" ? "no-store" : "no-cache",
        "Content-Length": content.length,
        "Content-Type": contentTypes[path.extname(file)]
    });
    response.end(request.method === "HEAD" ? undefined : content);
}

async function handleRequest(request, response) {
    securityHeaders(response);

    const url = new URL(request.url, `http://${request.headers.host || "localhost"}`);
    const pathname = url.pathname;

    if (pathname === "/api/messages" && request.method === "POST") {
        if (!isSameOrigin(request)) {
            sendJson(response, 403, { message: "Origem da solicitação não permitida." });
            return;
        }
        if (!requireJson(request, response)) return;

        const rateLimit = consumeRateLimit(
            getClientKey(request, "message"),
            10,
            10 * 60 * 1000
        );
        if (!rateLimit.allowed) {
            sendJson(
                response,
                429,
                { message: "Muitas mensagens. Aguarde antes de tentar novamente." },
                { "Retry-After": String(rateLimit.retryAfter) }
            );
            return;
        }

        const data = await readJson(request);
        const name = typeof data.name === "string" ? data.name.trim() : "";
        const email = typeof data.email === "string" ? data.email.trim() : "";
        const message = typeof data.message === "string" ? data.message.trim() : "";

        if (
            name.length < 2 ||
            name.length > 120 ||
            email.length > 254 ||
            !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) ||
            message.length < 10 ||
            message.length > 5000 ||
            data.consent !== true
        ) {
            sendJson(response, 400, { message: "Confira os dados e o consentimento do formulário." });
            return;
        }

        const messages = readMessages();
        if (messages.length >= maxMessages) {
            sendJson(response, 503, { message: "A caixa de mensagens está cheia no momento." });
            return;
        }

        messages.push({
            id: crypto.randomUUID(),
            name,
            email,
            message,
            createdAt: new Date().toISOString()
        });
        saveMessages(messages);
        sendJson(response, 201, { success: true });
        return;
    }

    if (pathname === "/api/admin/session" && request.method === "GET") {
        const session = getSession(request);
        if (!session) {
            sendJson(response, 401, { authenticated: false });
            return;
        }
        sendJson(response, 200, { authenticated: true });
        return;
    }

    if (pathname === "/api/admin/login" && request.method === "POST") {
        if (!isSameOrigin(request)) {
            sendJson(response, 403, { message: "Origem da solicitação não permitida." });
            return;
        }
        if (!requireJson(request, response)) return;

        const rateLimit = consumeRateLimit(
            getClientKey(request, "login"),
            5,
            15 * 60 * 1000
        );
        if (!rateLimit.allowed) {
            sendJson(
                response,
                429,
                { message: "Muitas tentativas de login. Aguarde antes de tentar novamente." },
                { "Retry-After": String(rateLimit.retryAfter) }
            );
            return;
        }

        const data = await readJson(request);
        const submittedPassword = typeof data.password === "string"
            ? data.password
            : "";
        const submittedHash = crypto.scryptSync(submittedPassword, passwordSalt, 32);

        if (!crypto.timingSafeEqual(passwordHash, submittedHash)) {
            sendJson(response, 401, { message: "Senha incorreta." });
            return;
        }

        const token = crypto.randomBytes(32).toString("hex");
        sessions.set(token, { expiresAt: Date.now() + sessionLifetimeMs });
        const cookieParts = [
            `portfolio_session=${token}`,
            "Path=/",
            "HttpOnly",
            "SameSite=Strict",
            `Max-Age=${sessionLifetimeMs / 1000}`
        ];
        if (isProduction) cookieParts.push("Secure");

        sendJson(
            response,
            200,
            { success: true },
            { "Set-Cookie": cookieParts.join("; ") }
        );
        return;
    }

    if (pathname === "/api/admin/logout" && request.method === "POST") {
        if (!isSameOrigin(request)) {
            sendJson(response, 403, { message: "Origem da solicitação não permitida." });
            return;
        }

        const session = getSession(request);
        if (session) sessions.delete(session.token);
        sendJson(response, 200, { success: true }, {
            "Set-Cookie": "portfolio_session=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0"
        });
        return;
    }

    if (pathname === "/api/admin/messages" && request.method === "GET") {
        if (!requireSession(request, response)) return;
        const messages = readMessages()
            .sort((first, second) => second.createdAt.localeCompare(first.createdAt));
        sendJson(response, 200, { messages });
        return;
    }

    if (request.method === "GET" || request.method === "HEAD") {
        servePublicFile(request, response, pathname);
        return;
    }

    sendJson(response, 405, { message: "Método não permitido." }, {
        Allow: "GET, HEAD"
    });
}

const port = Number(process.env.PORT || 8000);
if (!Number.isInteger(port) || port < 1 || port > 65535) {
    throw new Error("PORT precisa ser um número entre 1 e 65535.");
}

const host = process.env.HOST || (isProduction ? "0.0.0.0" : "127.0.0.1");
const server = http.createServer((request, response) => {
    handleRequest(request, response).catch(error => {
        console.error("Erro ao processar solicitação:", error);
        if (response.headersSent) {
            response.destroy();
            return;
        }

        sendJson(
            response,
            error.status || 500,
            { message: error.status ? error.message : "Erro interno do servidor." }
        );
    });
});

server.requestTimeout = 15_000;
server.headersTimeout = 10_000;
server.listen(port, host, () => {
    console.log(`Portfólio disponível em http://localhost:${port}`);
});
