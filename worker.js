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
   PREMIUM DEVICE TABLE SAFETY
========================================= */
async function ensurePremiumDeviceTable(env) {
    await env.DB.prepare(`
        CREATE TABLE IF NOT EXISTS key_devices (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            key_id INTEGER NOT NULL,
            device_id TEXT NOT NULL,
            first_seen_at INTEGER NOT NULL,
            last_seen_at INTEGER NOT NULL,
            UNIQUE(key_id, device_id)
        )
    `).run();
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
        await ensurePremiumDeviceTable(env);


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

        // Premium redemption uses key_devices.
        // Create the table before the first SELECT/INSERT so an existing D1
        // database from an older deployment does not fail with:
        // "no such table: key_devices".
        await ensurePremiumDeviceTable(env);

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
        - Binds to the first Roblox username.
        - Can be used on up to 5 stable devices.
        - Re-checking the same key on the same
          username/device must NOT say "already used".
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

            if (!deviceId || deviceId.length < 8 || deviceId.length > 200) {
                return json({
                    success: false,
                    message: "Device ID tidak valid."
                }, 400);
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

            const existingDevice = await env.DB.prepare(`
                SELECT id
                FROM key_devices
                WHERE key_id = ? AND device_id = ?
                LIMIT 1
            `).bind(row.id, deviceId).first();

            if (existingDevice) {
                await env.DB.prepare(`
                    UPDATE key_devices
                    SET last_seen_at = ?
                    WHERE id = ?
                `).bind(now, existingDevice.id).run();
            } else {
                await env.DB.prepare(`
                    INSERT OR IGNORE INTO key_devices
                        (key_id, device_id, first_seen_at, last_seen_at)
                    SELECT ?, ?, ?, ?
                    WHERE (SELECT COUNT(*) FROM key_devices WHERE key_id = ?) < 5
                `).bind(row.id, deviceId, now, now, row.id).run();

                const added = await env.DB.prepare(`
                    SELECT id
                    FROM key_devices
                    WHERE key_id = ? AND device_id = ?
                    LIMIT 1
                `).bind(row.id, deviceId).first();

                if (!added) {
                    const countRow = await env.DB.prepare(`
                        SELECT COUNT(*) AS total
                        FROM key_devices
                        WHERE key_id = ?
                    `).bind(row.id).first();

                    return json({
                        success: false,
                        message: "Batas 5 device untuk premium key ini sudah penuh.",
                        device_limit: 5,
                        device_count: Number(countRow?.total || 0)
                    }, 403);
                }
            }

            const countRow = await env.DB.prepare(`
                SELECT COUNT(*) AS total
                FROM key_devices
                WHERE key_id = ?
            `).bind(row.id).first();

            return json({
                success: true,
                message: "Premium aktif. Username Roblox cocok.",
                key: row.key,
                type: "PREMIUM",
                username: row.username,
                redeemed_at: Number(row.redeemed_at),
                expires_at: expiresAt,
                device_limit: 5,
                device_count: Number(countRow?.total || 0)
            });
        }


        /*
        =====================================
        CEK OWNER FREE KEY
        =====================================
        */

        if (
            row.type === "FREE" &&
            row.username !== username
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
        await ensurePremiumDeviceTable(env);
        const now = Date.now();
        let row = await env.DB.prepare(`
            SELECT id, key, type, username, duration_seconds, redeemed_at, expires_at, active
            FROM keys WHERE key = ? LIMIT 1
        `).bind(key).first();

        if (!row) return json({ success: false, message: "Key tidak ditemukan." }, 404);
        if (Number(row.active) !== 1) return json({ success: false, message: "Key sudah tidak aktif atau dicabut." }, 403);

        // Free keys remain bound to their generated Roblox username and must be redeemed first.
        if (row.type === "FREE") {
            if (row.username !== username) {
                return json({ success: false, message: "Key ini terikat dengan username Roblox lain." }, 403);
            }
            if (!row.redeemed_at) {
                return json({ success: false, message: "Free key belum diredeem." }, 409);
            }
        }

        // Premium keys bind permanently to the first Roblox username that activates them.
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

        // Device limits apply to premium keys only. Lua must send a stable device_id.
        let deviceCount = 0;
        if (row.type === "PREMIUM") {
            if (!deviceId || deviceId.length < 8 || deviceId.length > 200) {
                return json({ success: false, message: "Device ID tidak valid. Update script Lua agar mengirim device_id yang stabil." }, 400);
            }
            const existing = await env.DB.prepare(`
                SELECT id FROM key_devices WHERE key_id = ? AND device_id = ? LIMIT 1
            `).bind(row.id, deviceId).first();
            if (!existing) {
                // Enforce the cap in the INSERT statement itself to reduce race-condition overbooking.
                await env.DB.prepare(`
                    INSERT OR IGNORE INTO key_devices (key_id, device_id, first_seen_at, last_seen_at)
                    SELECT ?, ?, ?, ?
                    WHERE (SELECT COUNT(*) FROM key_devices WHERE key_id = ?) < 5
                `).bind(row.id, deviceId, now, now, row.id).run();
                const justAdded = await env.DB.prepare(`
                    SELECT id FROM key_devices WHERE key_id = ? AND device_id = ? LIMIT 1
                `).bind(row.id, deviceId).first();
                if (!justAdded) {
                    const countRow = await env.DB.prepare(`SELECT COUNT(*) AS total FROM key_devices WHERE key_id = ?`).bind(row.id).first();
                    deviceCount = Number(countRow?.total || 0);
                    return json({ success: false, message: "Batas 5 device untuk premium key ini sudah penuh.", device_limit: 5, device_count: deviceCount }, 403);
                }
            } else {
                await env.DB.prepare(`UPDATE key_devices SET last_seen_at = ? WHERE id = ?`).bind(now, existing.id).run();
            }
            const countAfter = await env.DB.prepare(`SELECT COUNT(*) AS total FROM key_devices WHERE key_id = ?`).bind(row.id).first();
            deviceCount = Number(countAfter?.total || 0);
        }

        return json({
            success: true,
            message: row.type === "PREMIUM" ? "Premium aktif. Username Roblox cocok." : "Key masih aktif.",
            key: row.key,
            type: row.type,
            username: row.username,
            redeemed_at: Number(row.redeemed_at),
            expires_at: expiresAt,
            device_limit: row.type === "PREMIUM" ? 5 : null,
            device_count: row.type === "PREMIUM" ? deviceCount : null
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

            return claimKey(
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
