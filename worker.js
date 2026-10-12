const JSON_HEADERS = {
    "Content-Type": "application/json; charset=UTF-8",
    "Cache-Control": "no-store"
};

function json(data, status = 200) {
    return new Response(
        JSON.stringify(data),
        {
            status,
            headers: JSON_HEADERS
        }
    );
}


/* =========================================
   KEY GENERATOR
========================================= */

function generateKey() {

    const chars =
        "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";

    function part() {

        let result = "";

        for (let i = 0; i < 5; i++) {

            result +=
                chars[
                    Math.floor(
                        Math.random() * chars.length
                    )
                ];

        }

        return result;
    }

    return `VRILZ-${part()}-${part()}-${part()}`;
}

function generatePremiumKey() {

    const chars =
        "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";

    function part() {

        let result = "";

        for (let i = 0; i < 5; i++) {
            result += chars[Math.floor(Math.random() * chars.length)];
        }

        return result;
    }

    return `VRILZ-PREM-${part()}-${part()}-${part()}`;
}


/* =========================================
   ADMIN AUTH
   Username/password + signed session token
========================================= */

const ADMIN_SESSION_TTL = 8 * 60 * 60 * 1000;

function base64url(input) {
    return btoa(String.fromCharCode(...new Uint8Array(input)))
        .replace(/\+/g, "-")
        .replace(/\//g, "_")
        .replace(/=+$/g, "");
}

function base64urlText(text) {
    return btoa(unescape(encodeURIComponent(text)))
        .replace(/\+/g, "-")
        .replace(/\//g, "_")
        .replace(/=+$/g, "");
}

function decodeBase64urlText(value) {
    const pad = value.length % 4 === 0 ? value : value + "=".repeat(4 - (value.length % 4));
    return decodeURIComponent(escape(atob(pad.replace(/-/g, "+").replace(/_/g, "/"))));
}

async function signAdminSession(payload, secret) {
    const body = base64urlText(JSON.stringify(payload));
    const key = await crypto.subtle.importKey(
        "raw",
        new TextEncoder().encode(secret),
        { name: "HMAC", hash: "SHA-256" },
        false,
        ["sign"]
    );
    const signature = await crypto.subtle.sign(
        "HMAC",
        key,
        new TextEncoder().encode(body)
    );
    return `${body}.${base64url(signature)}`;
}

async function verifyAdminSession(request, env) {
    const auth = request.headers.get("Authorization") || "";
    if (!auth.startsWith("Bearer ")) return false;

    const token = auth.slice(7).trim();
    const parts = token.split(".");
    if (parts.length !== 2 || !env.ADMIN_SESSION_SECRET) return false;

    try {
        const expected = await signAdminSession(
            JSON.parse(decodeBase64urlText(parts[0])),
            env.ADMIN_SESSION_SECRET
        );

        if (expected !== token) return false;

        const payload = JSON.parse(decodeBase64urlText(parts[0]));
        return payload.exp > Date.now() && payload.role === "admin";
    } catch {
        return false;
    }
}

async function adminLogin(request, env) {
    try {
        const body = await request.json();
        const username = String(body.username || "").trim();
        const password = String(body.password || "");

        if (!env.ADMIN_USERNAME || !env.ADMIN_PASSWORD || !env.ADMIN_SESSION_SECRET) {
            return json({
                success: false,
                message: "Admin secrets belum dikonfigurasi di Cloudflare Worker."
            }, 500);
        }

        if (username !== env.ADMIN_USERNAME || password !== env.ADMIN_PASSWORD) {
            return json({
                success: false,
                message: "Username atau password admin salah."
            }, 401);
        }

        const token = await signAdminSession({
            role: "admin",
            sub: username,
            exp: Date.now() + ADMIN_SESSION_TTL
        }, env.ADMIN_SESSION_SECRET);

        return json({
            success: true,
            token,
            expires_in: ADMIN_SESSION_TTL
        });
    } catch {
        return json({
            success: false,
            message: "Login admin gagal."
        }, 400);
    }
}

async function isAdmin(request, env) {
    return verifyAdminSession(request, env);
}

/* =========================================
   CLEAN EXPIRED KEYS
========================================= */

async function cleanupExpired(env) {

    const now = Date.now();

    /*
    Key FREE yang belum redeem
    dan sudah lewat 10 menit.
    */

    await env.DB
        .prepare(`
            UPDATE keys
            SET active = 0
            WHERE active = 1
            AND redeemed_at IS NULL
            AND claim_expires_at IS NOT NULL
            AND claim_expires_at <= ?
        `)
        .bind(now)
        .run();


    /*
    Key yang sudah redeem
    dan masa aktifnya habis.
    */

    await env.DB
        .prepare(`
            UPDATE keys
            SET active = 0
            WHERE active = 1
            AND redeemed_at IS NOT NULL
            AND expires_at IS NOT NULL
            AND expires_at <= ?
        `)
        .bind(now)
        .run();
}


/* =========================================
   PREMIUM KEY POLICY
   Premium is bound only to the first Roblox username.
   No device table / device limit is used.
========================================= */
async function ensurePremiumDeviceTable(env) {
    // Kept as a no-op for compatibility with older deployments.
    // Premium ownership is stored directly in keys.username.
    return;
}


/* =========================================
   LOOTLABS MISSION + BROWSER SESSION
========================================= */
const LOOTLABS_URL = "https://links.lootlabs.gg/s?rveZhVVu";
const SESSION_COOKIE = "vrilz_session";
const MONTHLY_CREATE_LIMIT = 3;
const MISSION_COOLDOWN_MS = 2 * 60 * 60 * 1000;

function randomToken(bytes = 24) {
    const data = new Uint8Array(bytes);
    crypto.getRandomValues(data);
    return Array.from(data, b => b.toString(16).padStart(2, "0")).join("");
}

function cookieValue(request, name) {
    const raw = request.headers.get("Cookie") || "";
    for (const part of raw.split(";")) {
        const i = part.indexOf("=");
        if (i > 0 && part.slice(0, i).trim() === name) return part.slice(i + 1).trim();
    }
    return "";
}

async function ensureMissionTables(env) {
    await env.DB.prepare(`CREATE TABLE IF NOT EXISTS loot_missions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        click_id TEXT NOT NULL UNIQUE,
        session_id TEXT NOT NULL,
        status TEXT NOT NULL DEFAULT 'started',
        unique_id TEXT,
        created_at INTEGER NOT NULL,
        completed_at INTEGER
    )`).run();
    await env.DB.prepare(`CREATE INDEX IF NOT EXISTS idx_loot_missions_session ON loot_missions(session_id, status, created_at)`).run();
    await env.DB.prepare(`CREATE TABLE IF NOT EXISTS browser_key_history (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        session_id TEXT NOT NULL,
        key_id INTEGER NOT NULL,
        created_at INTEGER NOT NULL,
        month_key TEXT NOT NULL,
        UNIQUE(session_id, key_id)
    )`).run();
    await env.DB.prepare(`CREATE INDEX IF NOT EXISTS idx_browser_key_history_month ON browser_key_history(session_id, month_key)`).run();
    await env.DB.prepare(`CREATE TABLE IF NOT EXISTS loot_postback_events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        unique_id TEXT NOT NULL UNIQUE,
        click_id TEXT NOT NULL,
        received_at INTEGER NOT NULL
    )`).run();
    await env.DB.prepare(`CREATE TABLE IF NOT EXISTS mission_action_cooldowns (
        session_id TEXT PRIMARY KEY,
        last_action_at INTEGER NOT NULL
    )`).run();
}

function monthKey(now = new Date()) {
    return `${now.getUTCFullYear()}-${String(now.getUTCMonth() + 1).padStart(2, "0")}`;
}

async function getOrSetSession(request) {
    const existing = cookieValue(request, SESSION_COOKIE);
    if (/^[a-f0-9]{48}$/.test(existing)) return { id: existing, setCookie: false };
    return { id: randomToken(24), setCookie: true };
}

function withSessionCookie(response, sessionId, shouldSet) {
    if (!shouldSet) return response;
    const headers = new Headers(response.headers);
    headers.append("Set-Cookie", `${SESSION_COOKIE}=${sessionId}; Path=/; Max-Age=31536000; HttpOnly; Secure; SameSite=Lax`);
    return new Response(response.body, { status: response.status, statusText: response.statusText, headers });
}

async function startLootMission(request, env) {
    try {
        await ensureMissionTables(env);
        const session = await getOrSetSession(request);
        const now = Date.now();
        // Cooldown starts only after a key is successfully created or renewed,
        // never merely because the user opened LootLabs without finishing it.
        const cooldownRow = await env.DB.prepare(`SELECT last_action_at FROM mission_action_cooldowns WHERE session_id = ? LIMIT 1`).bind(session.id).first();
        const lastActionAt = Number(cooldownRow?.last_action_at || 0);
        const remaining = MISSION_COOLDOWN_MS - (now - lastActionAt);
        if (lastActionAt && remaining > 0) {
            const response = json({ success: false, cooldown: true, remaining_ms: remaining, message: `You can start another mission in ${Math.ceil(remaining / 60000)} minute(s).` }, 429);
            return withSessionCookie(response, session.id, session.setCookie);
        }
        const clickId = randomToken(20);
        await env.DB.prepare(`INSERT INTO loot_missions (click_id, session_id, status, created_at) VALUES (?, ?, 'started', ?)`).bind(clickId, session.id, now).run();
        const link = `${LOOTLABS_URL}${LOOTLABS_URL.includes('?') ? '&' : '?'}puid=${encodeURIComponent(clickId)}`;
        return withSessionCookie(json({ success: true, mission_url: link, message: 'Misi dimulai. Selesaikan LootLabs, lalu kembali ke halaman ini.' }), session.id, session.setCookie);
    } catch (e) {
        return json({ success: false, message: 'Gagal memulai misi.' }, 500);
    }
}

async function lootMissionStatus(request, env) {
    try {
        await ensureMissionTables(env);
        const sessionId = cookieValue(request, SESSION_COOKIE);
        if (!/^[a-f0-9]{48}$/.test(sessionId)) return json({ success: true, verified: false, message: 'Mulai misi terlebih dahulu.' });
        const cooldownRow = await env.DB.prepare(`SELECT last_action_at FROM mission_action_cooldowns WHERE session_id = ? LIMIT 1`).bind(sessionId).first();
        const lastActionAt = Number(cooldownRow?.last_action_at || 0);
        const remaining = MISSION_COOLDOWN_MS - (Date.now() - lastActionAt);
        if (lastActionAt && remaining > 0) {
            return json({ success: true, verified: false, cooldown: true, remaining_ms: remaining, message: `Cooldown active for ${Math.ceil(remaining / 60000)} minute(s).` });
        }
        const mission = await env.DB.prepare(`SELECT status FROM loot_missions WHERE session_id = ? AND status = 'completed' ORDER BY created_at DESC LIMIT 1`).bind(sessionId).first();
        return json({ success: true, verified: !!mission, message: mission ? 'Misi berhasil diverifikasi.' : 'Misi belum terverifikasi.' });
    } catch {
        return json({ success: false, message: 'Gagal memeriksa status misi.' }, 500);
    }
}

async function lootLabsPostback(request, env, url) {
    try {
        await ensureMissionTables(env);
        if (!env.LOOTLABS_POSTBACK_SECRET) return new Response('Postback secret not configured', { status: 500 });
        const supplied = url.searchParams.get('secret') || request.headers.get('X-Postback-Secret') || '';
        if (supplied.length !== env.LOOTLABS_POSTBACK_SECRET.length || !crypto.subtle) return new Response('Forbidden', { status: 403 });
        const a = new TextEncoder().encode(supplied), b = new TextEncoder().encode(env.LOOTLABS_POSTBACK_SECRET);
        let diff = 0; for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
        if (diff !== 0) return new Response('Forbidden', { status: 403 });
        const clickId = String(url.searchParams.get('click_id') || '').trim();
        const uniqueId = String(url.searchParams.get('unique_id') || '').trim();
        if (!clickId || !uniqueId) return new Response('Missing click_id or unique_id', { status: 400 });
        const mission = await env.DB.prepare(`SELECT id, status FROM loot_missions WHERE click_id = ? LIMIT 1`).bind(clickId).first();
        if (!mission) return new Response('Unknown click_id', { status: 404 });
        try {
            await env.DB.prepare(`INSERT INTO loot_postback_events (unique_id, click_id, received_at) VALUES (?, ?, ?)`).bind(uniqueId, clickId, Date.now()).run();
        } catch (e) {
            // Duplicate postbacks are idempotent: a completed mission stays completed.
            const duplicate = await env.DB.prepare(`SELECT id FROM loot_postback_events WHERE unique_id = ?`).bind(uniqueId).first();
            if (!duplicate) throw e;
        }
        await env.DB.prepare(`UPDATE loot_missions SET status = 'completed', unique_id = ?, completed_at = ? WHERE click_id = ?`).bind(uniqueId, Date.now(), clickId).run();
        return new Response('OK', { status: 200, headers: { 'Content-Type': 'text/plain; charset=UTF-8', 'Cache-Control': 'no-store' } });
    } catch {
        return new Response('Postback error', { status: 500 });
    }
}

async function listSessionKeys(request, env) {
    try {
        await ensureMissionTables(env);
        const sessionId = cookieValue(request, SESSION_COOKIE);
        if (!/^[a-f0-9]{48}$/.test(sessionId)) return json({ success: true, keys: [] });
        const rows = await env.DB.prepare(`SELECT k.key, k.type, k.active, k.claim_expires_at, k.redeemed_at, k.expires_at, h.created_at
            FROM browser_key_history h JOIN keys k ON k.id = h.key_id
            WHERE h.session_id = ? ORDER BY h.created_at DESC`).bind(sessionId).all();
        const now = Date.now();
        const keys = (rows.results || []).map(k => {
            const exp = Number(k.expires_at || k.claim_expires_at || 0);
            const expired = exp > 0 && exp <= now;
            return { key: k.key, type: k.type || 'FREE', status: expired ? 'EXPIRED' : (k.redeemed_at ? 'ACTIVE' : 'READY'), expires_at: exp || null, time_left_ms: exp > now ? exp - now : 0, created_at: Number(k.created_at || 0) };
        });
        return json({ success: true, keys });
    } catch {
        return json({ success: false, keys: [], message: 'Gagal memuat daftar key.' }, 500);
    }
}

async function createOrRenewSessionKey(request, env) {
    try {
        await ensureMissionTables(env);
        const sessionId = cookieValue(request, SESSION_COOKIE);
        if (!/^[a-f0-9]{48}$/.test(sessionId)) return json({ success: false, message: 'Sesi browser tidak ditemukan. Klik START terlebih dahulu.' }, 400);
        const now = Date.now();
        const cooldownRow = await env.DB.prepare(`SELECT last_action_at FROM mission_action_cooldowns WHERE session_id = ? LIMIT 1`).bind(sessionId).first();
        const lastActionAt = Number(cooldownRow?.last_action_at || 0);
        const cooldownRemaining = MISSION_COOLDOWN_MS - (now - lastActionAt);
        if (lastActionAt && cooldownRemaining > 0) {
            return json({ success: false, cooldown: true, remaining_ms: cooldownRemaining, message: `You can create or renew another key in ${Math.ceil(cooldownRemaining / 60000)} minute(s).` }, 429);
        }
        // Use a completed, unused mission. An unfinished redirect does not consume
        // the 2-hour cooldown, and the user can start another mission.
        const latest = await env.DB.prepare(`SELECT id, status FROM loot_missions WHERE session_id = ? AND status = 'completed' ORDER BY created_at DESC LIMIT 1`).bind(sessionId).first();
        if (!latest) return json({ success: false, message: 'Selesaikan misi LootLabs sampai terverifikasi terlebih dahulu.' }, 403);
        const existing = await env.DB.prepare(`SELECT k.id, k.key, k.active, k.expires_at, k.redeemed_at, k.claim_expires_at
            FROM browser_key_history h JOIN keys k ON k.id = h.key_id
            WHERE h.session_id = ? ORDER BY h.created_at DESC LIMIT 1`).bind(sessionId).first();
        const redeemedExpired = existing && Number(existing.expires_at || 0) > 0 && Number(existing.expires_at) <= now;
        const neverRedeemedExpired = existing && !existing.redeemed_at && Number(existing.claim_expires_at || 0) > 0 && Number(existing.claim_expires_at) <= now;
        if (redeemedExpired || neverRedeemedExpired) {
            await env.DB.prepare(`UPDATE keys SET active = 1, type = 'FREE', duration_seconds = 86400, claimed_at = ?, claim_expires_at = ?, redeemed_at = NULL, expires_at = NULL WHERE id = ?`).bind(now, now + 10 * 60 * 1000, existing.id).run();
            await env.DB.prepare(`UPDATE loot_missions SET status = 'used' WHERE id = ?`).bind(latest.id).run();
            await env.DB.prepare(`INSERT INTO mission_action_cooldowns (session_id, last_action_at) VALUES (?, ?) ON CONFLICT(session_id) DO UPDATE SET last_action_at = excluded.last_action_at`).bind(sessionId, now).run();
            return json({ success: true, key: existing.key, renewed: true, cooldown_ms: MISSION_COOLDOWN_MS, message: 'Key lama berhasil diperbarui. Redeem dalam 10 menit; masa aktif 24 jam dimulai saat redeem. Mission cooldown: 2 hours.' });
        }
        const month = monthKey(new Date(now));
        const countRow = await env.DB.prepare(`SELECT COUNT(*) AS count FROM browser_key_history WHERE session_id = ? AND month_key = ?`).bind(sessionId, month).first();
        if (Number(countRow?.count || 0) >= MONTHLY_CREATE_LIMIT) return json({ success: false, message: 'Batas Create Key bulan ini sudah mencapai 3 kali. Key expired tetap bisa diperbarui setelah misi selesai.' }, 429);
        let newKey, exists;
        do { newKey = generateKey(); exists = await env.DB.prepare(`SELECT id FROM keys WHERE key = ? LIMIT 1`).bind(newKey).first(); } while (exists);
        await env.DB.prepare(`INSERT INTO keys (key, type, username, duration_seconds, claimed_at, claim_expires_at, redeemed_at, expires_at, active, created_at) VALUES (?, 'FREE', NULL, 86400, ?, ?, NULL, NULL, 1, ?)`).bind(newKey, now, now + 10 * 60 * 1000, now).run();
        const row = await env.DB.prepare(`SELECT id FROM keys WHERE key = ? LIMIT 1`).bind(newKey).first();
        await env.DB.prepare(`INSERT INTO browser_key_history (session_id, key_id, created_at, month_key) VALUES (?, ?, ?, ?)`).bind(sessionId, row.id, now, month).run();
        await env.DB.prepare(`UPDATE loot_missions SET status = 'used' WHERE id = ?`).bind(latest.id).run();
        await env.DB.prepare(`INSERT INTO mission_action_cooldowns (session_id, last_action_at) VALUES (?, ?) ON CONFLICT(session_id) DO UPDATE SET last_action_at = excluded.last_action_at`).bind(sessionId, now).run();
        return json({ success: true, key: newKey, renewed: false, cooldown_ms: MISSION_COOLDOWN_MS, message: 'Key berhasil dibuat. Redeem dalam 10 menit; masa aktif 24 jam dimulai saat redeem. Mission cooldown: 2 hours.' });
    } catch (e) {
        return json({ success: false, message: 'Terjadi kesalahan server saat membuat key.' }, 500);
    }
}


/* =========================================
   USER CLAIM
========================================= */

async function claimKey(request, env) {

    try {

        const body =
            await request.json();

        const username =
            String(
                body.username || ""
            ).trim();


        if (!username) {

            return json({
                success: false,
                message: "Username wajib diisi."
            }, 400);

        }


        if (username.length < 2) {

            return json({
                success: false,
                message: "Username terlalu pendek."
            }, 400);

        }


        if (username.length > 50) {

            return json({
                success: false,
                message: "Username terlalu panjang."
            }, 400);

        }


        await cleanupExpired(env);


        const now =
            Date.now();

        const cooldown =
            24 * 60 * 60 * 1000;

        const redeemWindow =
            10 * 60 * 1000;


        /*
        =====================================
        CEK USER
        =====================================
        */

        await env.DB
            .prepare(`
                INSERT INTO users (
                    username,
                    created_at
                )
                VALUES (?, ?)
                ON CONFLICT(username)
                DO NOTHING
            `)
            .bind(
                username,
                now
            )
            .run();


        /*
        =====================================
        CEK CLAIM TERAKHIR
        =====================================
        */

        const previous =
            await env.DB
                .prepare(`
                    SELECT
                        claimed_at
                    FROM keys
                    WHERE username = ?
                    AND claimed_at IS NOT NULL
                    ORDER BY claimed_at DESC
                    LIMIT 1
                `)
                .bind(username)
                .first();


        if (previous) {

            const lastClaim =
                Number(
                    previous.claimed_at
                );

            const nextClaim =
                lastClaim + cooldown;


            if (now < nextClaim) {

                const remaining =
                    nextClaim - now;

                const hours =
                    Math.floor(
                        remaining /
                        3600000
                    );

                const minutes =
                    Math.ceil(
                        (
                            remaining %
                            3600000
                        ) / 60000
                    );

                return json({

                    success: false,

                    message:
                        `Kamu sudah claim key. Tunggu ${hours} jam ${minutes} menit lagi.`,

                    next_claim:
                        nextClaim

                }, 429);

            }

        }


        /*
        =====================================
        GENERATE UNIQUE KEY
        =====================================
        */

        let newKey;
        let exists;

        do {

            newKey =
                generateKey();

            exists =
                await env.DB
                    .prepare(`
                        SELECT id
                        FROM keys
                        WHERE key = ?
                        LIMIT 1
                    `)
                    .bind(newKey)
                    .first();

        } while (exists);


        const claimedAt =
            now;

        const claimExpiresAt =
            now + redeemWindow;


        /*
        =====================================
        SIMPAN
        =====================================
        */

        await env.DB
            .prepare(`
                INSERT INTO keys (
                    key,
                    type,
                    username,
                    duration_seconds,
                    claimed_at,
                    claim_expires_at,
                    redeemed_at,
                    expires_at,
                    active,
                    created_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            `)
            .bind(
                newKey,
                "FREE",
                username,
                86400,
                claimedAt,
                claimExpiresAt,
                null,
                null,
                1,
                now
            )
            .run();


        return json({

            success: true,

            message:
                "Key berhasil dibuat.",

            key:
                newKey,

            claimed_at:
                claimedAt,

            claim_expires_at:
                claimExpiresAt

        });

    } catch (error) {

        return json({

            success: false,

            message:
                "Terjadi kesalahan server."

        }, 500);

    }

}


/* =========================================
   REDEEM
========================================= */

async function redeemKey(request, env) {

    try {

        const body =
            await request.json();

        const username =
            String(
                body.username || ""
            ).trim();

        const key =
            String(
                body.key || ""
            ).trim()
            .toUpperCase();

        const deviceId =
            String(
                body.device_id || body.deviceId || ""
            ).trim();


        if (!username || !key) {

            return json({
                success: false,
                message:
                    "Username dan key wajib diisi."
            }, 400);

        }


        await cleanupExpired(env);

        const now =
            Date.now();


        let row =
            await env.DB
                .prepare(`
                    SELECT
                        id,
                        key,
                        type,
                        username,
                        duration_seconds,
                        claimed_at,
                        claim_expires_at,
                        redeemed_at,
                        expires_at,
                        active
                    FROM keys
                    WHERE key = ?
                    LIMIT 1
                `)
                .bind(key)
                .first();


        if (!row) {

            return json({
                success: false,
                message:
                    "Key tidak ditemukan."
            }, 404);

        }


        /*
        =====================================
        KEY SUDAH EXPIRED
        =====================================
        */

        if (
            Number(row.active) !== 1
        ) {

            return json({
                success: false,
                message:
                    "Key sudah expired atau tidak aktif."
            });

        }


        /*
        =====================================
        PREMIUM KEY
        - Binds permanently to the first Roblox username.
        - No device limit is used.
        - The same Roblox username can redeem/verify
          the key repeatedly until it expires.
        =====================================
        */

        if (row.type === "PREMIUM") {
            if (row.username && row.username.toLowerCase() !== username.toLowerCase()) {
                return json({
                    success: false,
                    message: "Premium key ini sudah terikat dengan username Roblox lain."
                }, 403);
            }

            // First activation: bind the premium key to this Roblox username.
            if (!row.username || !row.redeemed_at) {
                const duration = Number(row.duration_seconds) || 86400;
                const expiresAt = now + duration * 1000;

                await env.DB.prepare(`
                    UPDATE keys
                    SET username = ?, redeemed_at = ?, expires_at = ?, active = 1
                    WHERE id = ? AND (username IS NULL OR username = ?) AND redeemed_at IS NULL
                `).bind(username, now, expiresAt, row.id, username).run();

                const refreshed = await env.DB.prepare(`
                    SELECT id, key, type, username, duration_seconds, redeemed_at, expires_at, active
                    FROM keys WHERE id = ? LIMIT 1
                `).bind(row.id).first();

                if (!refreshed || !refreshed.username ||
                    String(refreshed.username).toLowerCase() !== username.toLowerCase()) {
                    return json({
                        success: false,
                        message: "Premium key sedang diaktifkan oleh username lain. Coba lagi."
                    }, 409);
                }

                row = refreshed;
            }

            if (!row.redeemed_at) {
                return json({
                    success: false,
                    message: "Premium key belum aktif."
                }, 409);
            }

            const expiresAt = Number(row.expires_at || 0);
            if (!expiresAt || now >= expiresAt) {
                await env.DB.prepare(`
                    UPDATE keys SET active = 0 WHERE id = ?
                `).bind(row.id).run();

                return json({
                    success: false,
                    message: "Premium key sudah expired.",
                    expired: true,
                    type: "PREMIUM",
                    expires_at: expiresAt
                });
            }

            // Premium has NO device binding. Once the key is activated,
            // only the first Roblox username stored in keys.username may use it.
            return json({
                success: true,
                message: "Premium aktif. Username Roblox cocok.",
                key: row.key,
                type: "PREMIUM",
                username: row.username,
                redeemed_at: Number(row.redeemed_at),
                expires_at: expiresAt
            });
        }


        /*
        =====================================
        CEK OWNER FREE KEY
        =====================================
        */

        if (
            row.type === "FREE" &&
            row.username && row.username !== username
        ) {

            return json({
                success: false,
                message:
                    "Key ini terikat dengan username lain."
            }, 403);

        }


        /*
        =====================================
        SUDAH REDEEM
        =====================================
        */

        if (
            row.redeemed_at !== null
        ) {

            if (
                row.expires_at &&
                now >= Number(row.expires_at)
            ) {

                await env.DB
                    .prepare(`
                        UPDATE keys
                        SET active = 0
                        WHERE id = ?
                    `)
                    .bind(row.id)
                    .run();

                return json({
                    success: false,
                    message:
                        "Key sudah expired."
                });

            }


            return json({
                success: false,
                message:
                    "Key sudah pernah digunakan."
            });

        }


        /*
        =====================================
        FREE KEY 10 MENIT
        =====================================
        */

        if (
            row.claim_expires_at &&
            now >=
            Number(row.claim_expires_at)
        ) {

            await env.DB
                .prepare(`
                    UPDATE keys
                    SET active = 0
                    WHERE id = ?
                `)
                .bind(row.id)
                .run();

            return json({
                success: false,
                message:
                    "Key sudah expired karena tidak digunakan dalam 10 menit."
            });

        }


        /*
        =====================================
        AKTIFKAN KEY
        =====================================
        */

        const duration =
            Number(
                row.duration_seconds
            ) || 86400;

        const redeemedAt =
            now;

        const expiresAt =
            now +
            (
                duration *
                1000
            );


        await env.DB
            .prepare(`
                UPDATE keys
                SET
                    username = ?,
                    redeemed_at = ?,
                    expires_at = ?,
                    active = 1
                WHERE id = ?
            `)
            .bind(
                username,
                redeemedAt,
                expiresAt,
                row.id
            )
            .run();


        return json({

            success: true,

            message:
                "Key berhasil diredeem.",

            key:
                row.key,

            type:
                row.type,

            redeemed_at:
                redeemedAt,

            expires_at:
                expiresAt

        });

     } catch (error) {
        return json({
            success: false,
            message: "PREMIUM ERROR: " + String(error?.message || error)
        }, 500);
    }

}


/* =========================================
   ADMIN CREATE PREMIUM KEY
========================================= */

async function adminCreateKey(
    request,
    env
) {

    if (!(await isAdmin(request, env))) {

        return json({
            success: false,
            message:
                "Unauthorized."
        }, 401);

    }


    try {

        const body =
            await request.json();

        const durationDays =
            Number(
                body.duration_days
            );


        const allowed = [
            1,
            3,
            7,
            30,
            90,
            365
        ];


        if (
            !allowed.includes(
                durationDays
            )
        ) {

            return json({
                success: false,
                message:
                    "Durasi tidak valid."
            }, 400);

        }


        const now =
            Date.now();

        const durationSeconds =
            durationDays *
            24 *
            60 *
            60;


        let newKey;
        let exists;


        do {

            newKey =
                generatePremiumKey();

            exists =
                await env.DB
                    .prepare(`
                        SELECT id
                        FROM keys
                        WHERE key = ?
                        LIMIT 1
                    `)
                    .bind(newKey)
                    .first();

        } while (exists);


        await env.DB
            .prepare(`
                INSERT INTO keys (
                    key,
                    type,
                    username,
                    duration_seconds,
                    claimed_at,
                    claim_expires_at,
                    redeemed_at,
                    expires_at,
                    active,
                    created_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            `)
            .bind(
                newKey,
                "PREMIUM",
                null,
                durationSeconds,
                null,
                null,
                null,
                null,
                1,
                now
            )
            .run();


        return json({

            success: true,

            message:
                "Premium key berhasil dibuat.",

            key:
                newKey,

            duration_days:
                durationDays

        });

    } catch (error) {

        return json({

            success: false,
            message:
                "Gagal membuat premium key."

        }, 500);

    }

}


/* =========================================
   ADMIN LIST KEYS
========================================= */

async function adminListKeys(
    request,
    env
) {

    if (!(await isAdmin(request, env))) {

        return json({
            success: false,
            message:
                "Unauthorized."
        }, 401);

    }


    await cleanupExpired(env);


    const result =
        await env.DB
            .prepare(`
                SELECT
                    id,
                    key,
                    type,
                    username,
                    duration_seconds,
                    claimed_at,
                    claim_expires_at,
                    redeemed_at,
                    expires_at,
                    active,
                    created_at
                FROM keys
                ORDER BY id DESC
                LIMIT 200
            `)
            .all();


    return json({

        success: true,

        keys:
            result.results || []

    });

}


/* =========================================
   ADMIN REVOKE
========================================= */

async function adminRevoke(
    request,
    env
) {

    if (!(await isAdmin(request, env))) {

        return json({
            success: false,
            message:
                "Unauthorized."
        }, 401);

    }


    try {

        const body =
            await request.json();

        const id =
            Number(body.id);


        if (!id) {

            return json({
                success: false,
                message:
                    "ID key tidak valid."
            }, 400);

        }


        await env.DB
            .prepare(`
                UPDATE keys
                SET active = 0
                WHERE id = ?
            `)
            .bind(id)
            .run();


        return json({

            success: true,

            message:
                "Key berhasil di-revoke."

        });

    } catch (error) {

        return json({

            success: false,
            message:
                "Gagal revoke key."

        }, 500);

    }

}


/* =========================================
   ADMIN DELETE
========================================= */

async function adminDelete(
    request,
    env
) {

    if (!(await isAdmin(request, env))) {

        return json({
            success: false,
            message:
                "Unauthorized."
        }, 401);

    }


    try {

        const body =
            await request.json();

        const id =
            Number(body.id);


        if (!id) {

            return json({
                success: false,
                message:
                    "ID key tidak valid."
            }, 400);

        }


        await env.DB
            .prepare(`
                DELETE FROM keys
                WHERE id = ?
            `)
            .bind(id)
            .run();


        return json({

            success: true,

            message:
                "Key berhasil dihapus."

        });

    } catch (error) {

        return json({

            success: false,

            message:
                "Gagal menghapus key."

        }, 500);

    }

}


/* =========================================
   VERIFY REDEEMED KEY
========================================= */

async function verifyKey(request, env) {
    try {
        const body = await request.json();
        const username = String(body.username || "").trim();
        const key = String(body.key || "").trim().toUpperCase();
        const deviceId = String(body.device_id || body.deviceId || "").trim();

        if (!username || !key) {
            return json({ success: false, message: "Username Roblox dan key wajib diisi." }, 400);
        }
        if (username.length < 2 || username.length > 50) {
            return json({ success: false, message: "Username Roblox tidak valid." }, 400);
        }

        await cleanupExpired(env);
        const now = Date.now();
        let row = await env.DB.prepare(`
            SELECT id, key, type, username, duration_seconds, redeemed_at, expires_at, active
            FROM keys WHERE key = ? LIMIT 1
        `).bind(key).first();

        if (!row) return json({ success: false, message: "Key tidak ditemukan." }, 404);
        if (Number(row.active) !== 1) return json({ success: false, message: "Key sudah tidak aktif atau dicabut." }, 403);

        // Free keys remain bound to their generated Roblox username and must be redeemed first.
        if (row.type === "FREE") {
            if (row.username && row.username !== username) {
                return json({ success: false, message: "Key ini terikat dengan username Roblox lain." }, 403);
            }
            if (!row.redeemed_at) {
                return json({ success: false, message: "Free key belum diredeem." }, 409);
            }
        }

        // Premium keys bind permanently to the first Roblox username that activates them.
        // No device limit is used.
        if (row.type === "PREMIUM") {
            if (row.username && row.username.toLowerCase() !== username.toLowerCase()) {
                return json({ success: false, message: "Premium key ini sudah terikat dengan username Roblox lain." }, 403);
            }
            if (!row.username || !row.redeemed_at) {
                const duration = Number(row.duration_seconds) || 86400;
                const expiresAt = now + duration * 1000;
                await env.DB.prepare(`
                    UPDATE keys SET username = ?, redeemed_at = ?, expires_at = ?, active = 1
                    WHERE id = ? AND username IS NULL AND redeemed_at IS NULL
                `).bind(username, now, expiresAt, row.id).run();
                row = await env.DB.prepare(`
                    SELECT id, key, type, username, duration_seconds, redeemed_at, expires_at, active
                    FROM keys WHERE id = ? LIMIT 1
                `).bind(row.id).first();
                if (!row || String(row.username).toLowerCase() !== username.toLowerCase()) {
                    return json({ success: false, message: "Premium key sedang diaktifkan oleh username lain. Coba lagi." }, 409);
                }
            }
        }

        if (!row.redeemed_at) {
            return json({ success: false, message: "Key belum pernah diaktifkan." }, 409);
        }

        const expiresAt = Number(row.expires_at || 0);
        if (!expiresAt || now >= expiresAt) {
            await env.DB.prepare(`UPDATE keys SET active = 0 WHERE id = ?`).bind(row.id).run();
            return json({ success: false, message: "Key sudah expired.", expired: true, type: row.type, expires_at: expiresAt });
        }

        return json({
            success: true,
            message: row.type === "PREMIUM" ? "Premium aktif. Username Roblox cocok." : "Key masih aktif.",
            key: row.key,
            type: row.type,
            username: row.username,
            redeemed_at: Number(row.redeemed_at),
            expires_at: expiresAt
        });
     } catch (error) {
        return json({
            success: false,
            message: "VERIFY PREMIUM ERROR: " + String(error?.message || error)
        }, 500);
    }
}

/* =========================================
   GLOBAL CHAT (pakai CHAT_DB)
========================================= */

const CHAT_MAX = 200;
const CHAT_RATE_LIMIT_MS = 1500;
const CHAT_MAX_LEN = 200;

async function handleChatSend(request, env) {
    try {
        const body = await request.json();
        const userId = Number(body.userId || 0);
        const username = String(body.username || "unknown").slice(0, 32).trim();
        const displayName = String(body.displayName || username).slice(0, 32).trim();
        let text = String(body.text || "").slice(0, CHAT_MAX_LEN);
        text = text.replace(/[\n\r]/g, " ").trim();

        if (!text) return json({ success: false, message: "Empty message" }, 400);
        if (!userId || !username) return json({ success: false, message: "Missing user info" }, 400);

        const now = Date.now();

        const last = await env.CHAT_DB.prepare(`
            SELECT created_at FROM chat_messages
            WHERE user_id = ?
            ORDER BY created_at DESC LIMIT 1
        `).bind(userId).first();

        if (last && now - Number(last.created_at) < CHAT_RATE_LIMIT_MS) {
            return json({ success: false, message: "Slow down (rate limit)" }, 429);
        }

        await env.CHAT_DB.prepare(`
            INSERT INTO chat_messages (user_id, username, display_name, text, created_at)
            VALUES (?, ?, ?, ?, ?)
        `).bind(userId, username, displayName, text, now).run();

        await env.CHAT_DB.prepare(`
            DELETE FROM chat_messages
            WHERE id NOT IN (
                SELECT id FROM chat_messages ORDER BY id DESC LIMIT ?
            )
        `).bind(CHAT_MAX).run();

        return json({ success: true, ts: now });
    } catch (error) {
        return json({ success: false, message: "Server error", error: String(error) }, 500);
    }
}

async function handleChatPoll(request, env) {
    try {
        const url = new URL(request.url);
        const since = Number(url.searchParams.get("since") || 0);

        const result = await env.CHAT_DB.prepare(`
            SELECT user_id, username, display_name, text, created_at
            FROM chat_messages
            WHERE created_at > ?
            ORDER BY created_at ASC
            LIMIT 100
        `).bind(since).all();

        const messages = (result.results || []).map(m => ({
            i: Number(m.user_id),
            u: m.username,
            d: m.display_name,
            t: m.text,
            ts: Number(m.created_at),
        }));

        return json({ success: true, messages });
    } catch (error) {
        return json({ success: false, message: "Server error", messages: [], error: String(error) }, 500);
    }
}


/* =========================================
   MAIN WORKER
========================================= */

export default {

    async fetch(
        request,
        env
    ) {

        const url =
            new URL(request.url);


        /*
        =====================================
        CORS
        =====================================
        */

        if (
            request.method === "OPTIONS"
        ) {

            return new Response(
                null,
                {
                    status: 204,
                    headers: {
                        "Access-Control-Allow-Origin": "*",
                        "Access-Control-Allow-Methods":
                            "GET, POST, OPTIONS",
                        "Access-Control-Allow-Headers":
                            "Content-Type, Authorization"
                    }
                }
            );

        }


        /*
        =====================================
        GLOBAL CHAT ROUTES
        =====================================
        */

        if (
            url.pathname === "/api/chat/send"
        ) {

            if (request.method !== "POST") {
                return json({
                    success: false,
                    message: "Method not allowed."
                }, 405);
            }

            return handleChatSend(
                request,
                env
            );

        }


        if (
            url.pathname === "/api/chat/poll"
        ) {

            if (request.method !== "GET") {
                return json({
                    success: false,
                    message: "Method not allowed."
                }, 405);
            }

            return handleChatPoll(
                request,
                env
            );

        }


        /*
        =====================================
        API ROUTES
        =====================================
        */

        if (url.pathname === "/api/keys/list") {
            if (request.method !== "GET") return json({ success: false, message: "Method not allowed." }, 405);
            return listSessionKeys(request, env);
        }

        if (url.pathname === "/api/mission/start") {
            if (request.method !== "POST") return json({ success: false, message: "Method not allowed." }, 405);
            return startLootMission(request, env);
        }

        if (url.pathname === "/api/mission/status") {
            if (request.method !== "GET") return json({ success: false, message: "Method not allowed." }, 405);
            return lootMissionStatus(request, env);
        }

        if (url.pathname === "/api/lootlabs/postback") {
            if (request.method !== "GET") return new Response("Method not allowed", { status: 405 });
            return lootLabsPostback(request, env, url);
        }

        if (
            url.pathname === "/api/claim"
        ) {

            if (
                request.method !== "POST"
            ) {

                return json({
                    success: false,
                    message:
                        "Method not allowed."
                }, 405);

            }

            return createOrRenewSessionKey(
                request,
                env
            );

        }


        if (
            url.pathname === "/api/verify"
        ) {

            if (request.method !== "POST") {
                return json({
                    success: false,
                    message: "Method not allowed."
                }, 405);
            }

            return verifyKey(
                request,
                env
            );
        }


        if (
            url.pathname === "/api/redeem"
        ) {

            if (
                request.method !== "POST"
            ) {

                return json({
                    success: false,
                    message:
                        "Method not allowed."
                }, 405);

            }

            return redeemKey(
                request,
                env
            );

        }


        if (
            url.pathname ===
            "/api/admin/login"
        ) {

            if (request.method !== "POST") {
                return json({
                    success: false,
                    message: "Method not allowed."
                }, 405);
            }

            return adminLogin(request, env);
        }


        if (
            url.pathname ===
            "/api/admin/create"
        ) {

            if (
                request.method !== "POST"
            ) {

                return json({
                    success: false,
                    message:
                        "Method not allowed."
                }, 405);

            }

            return adminCreateKey(
                request,
                env
            );

        }


        if (
            url.pathname ===
            "/api/admin/keys"
        ) {

            if (
                request.method !== "GET"
            ) {

                return json({
                    success: false,
                    message:
                        "Method not allowed."
                }, 405);

            }

            return adminListKeys(
                request,
                env
            );

        }


        if (
            url.pathname ===
            "/api/admin/revoke"
        ) {

            if (
                request.method !== "POST"
            ) {

                return json({
                    success: false,
                    message:
                        "Method not allowed."
                }, 405);

            }

            return adminRevoke(
                request,
                env
            );

        }


        if (
            url.pathname ===
            "/api/admin/delete"
        ) {

            if (
                request.method !== "POST"
            ) {

                return json({
                    success: false,
                    message:
                        "Method not allowed."
                }, 405);

            }

            return adminDelete(
                request,
                env
            );

        }


        /*
        =====================================
        ROOT
        =====================================
        */

        if (
            url.pathname === "/" &&
            env.ASSETS
        ) {

            return env.ASSETS.fetch(
                new Request(
                    new URL("/index.html", request.url),
                    request
                )
            );

        }


        /*
        =====================================
        STATIC FILES
        =====================================
        */

        if (env.ASSETS) {

            return env.ASSETS.fetch(
                request
            );

        }


        return json({

            success: false,

            message:
                "Endpoint tidak ditemukan."

        }, 404);

    }

};
