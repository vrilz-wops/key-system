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


/* =========================================
   ADMIN AUTH
========================================= */

function isAdmin(request, env) {

    const auth =
        request.headers.get("Authorization");

    if (!auth) {
        return false;
    }

    if (!auth.startsWith("Bearer ")) {
        return false;
    }

    const token =
        auth.slice(7).trim();

    return Boolean(
        env.ADMIN_TOKEN &&
        token &&
        token === env.ADMIN_TOKEN
    );
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


        const row =
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

            message:
                "Terjadi kesalahan server."

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

    if (!isAdmin(request, env)) {

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

    if (!isAdmin(request, env)) {

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

    if (!isAdmin(request, env)) {

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

    if (!isAdmin(request, env)) {

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
