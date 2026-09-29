const json = (data, status = 200) => {
    return new Response(JSON.stringify(data), {
        status,
        headers: {
            "Content-Type": "application/json"
        }
    });
};

function generateKey() {
    const chars = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";

    let part1 = "";
    let part2 = "";
    let part3 = "";

    for (let i = 0; i < 4; i++) {
        part1 += chars[Math.floor(Math.random() * chars.length)];
        part2 += chars[Math.floor(Math.random() * chars.length)];
        part3 += chars[Math.floor(Math.random() * chars.length)];
    }

    return `VRILZ-${part1}-${part2}-${part3}`;
}

export default {

    async fetch(request, env) {

        const url = new URL(request.url);

        /*
        ========================================
        TEST
        ========================================
        */

        if (url.pathname === "/" && request.method === "GET") {

            return json({
                success: true,
                message: "VRILZ Key System API aktif"
            });

        }


        /*
        ========================================
        CLAIM FREE KEY
        ========================================
        */

        if (
            url.pathname === "/api/claim" &&
            request.method === "POST"
        ) {

            try {

                const body = await request.json();

                const username =
                    String(body.username || "").trim();


                if (!username) {

                    return json({
                        success: false,
                        message: "Username wajib diisi."
                    }, 400);

                }


                /*
                ========================================
                WAKTU
                ========================================
                */

                const now = Date.now();

                const cooldown =
                    24 * 60 * 60 * 1000;

                const claimLimit =
                    10 * 60 * 1000;


                /*
                ========================================
                CEK CLAIM SEBELUMNYA
                ========================================
                */

                const previous = await env.DB
                    .prepare(`
                        SELECT
                            id,
                            key,
                            claimed_at,
                            claim_expires_at,
                            redeemed_at,
                            expires_at,
                            active
                        FROM keys
                        WHERE username = ?
                        ORDER BY claimed_at DESC
                        LIMIT 1
                    `)
                    .bind(username)
                    .first();


                if (previous) {

                    const nextClaim =
                        Number(previous.claimed_at) + cooldown;


                    if (now < nextClaim) {

                        const remaining =
                            nextClaim - now;

                        const minutes =
                            Math.ceil(
                                remaining / 60000
                            );

                        return json({
                            success: false,
                            message:
                                `Kamu sudah claim key. Coba lagi dalam ${minutes} menit.`,
                            next_claim: nextClaim
                        }, 429);

                    }

                }


                /*
                ========================================
                BUAT KEY BARU
                ========================================
                */

                let newKey = generateKey();


                /*
                Pastikan key tidak duplikat
                */

                let exists = await env.DB
                    .prepare(`
                        SELECT id
                        FROM keys
                        WHERE key = ?
                        LIMIT 1
                    `)
                    .bind(newKey)
                    .first();


                while (exists) {

                    newKey = generateKey();

                    exists = await env.DB
                        .prepare(`
                            SELECT id
                            FROM keys
                            WHERE key = ?
                            LIMIT 1
                        `)
                        .bind(newKey)
                        .first();

                }


                /*
                ========================================
                WAKTU CLAIM
                ========================================
                */

                const claimedAt = now;

                const claimExpiresAt =
                    now + claimLimit;


                /*
                ========================================
                SIMPAN
                ========================================
                */

                await env.DB
                    .prepare(`
                        INSERT INTO keys (
                            key,
                            type,
                            username,
                            claimed_at,
                            claim_expires_at,
                            redeemed_at,
                            expires_at,
                            active,
                            created_at
                        )
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    `)
                    .bind(
                        newKey,
                        "FREE",
                        username,
                        claimedAt,
                        claimExpiresAt,
                        null,
                        null,
                        1,
                        now
                    )
                    .run();


                /*
                ========================================
                RESPONSE
                ========================================
                */

                return json({

                    success: true,

                    message:
                        "Key berhasil dibuat.",

                    key: newKey,

                    claimed_at:
                        claimedAt,

                    claim_expires_at:
                        claimExpiresAt

                });

            } catch (error) {

                return json({

                    success: false,

                    message:
                        "Terjadi kesalahan pada server."

                }, 500);

            }

        }


        /*
        ========================================
        ENDPOINT TIDAK DITEMUKAN
        ========================================
        */

        return json({

            success: false,

            message:
                "Endpoint tidak ditemukan."

        }, 404);

    }

};
