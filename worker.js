export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    // TEST API
    if (url.pathname === "/") {
      return Response.json({
        success: true,
        message: "Key System API aktif"
      });
    }

    // VALIDATE KEY
    if (url.pathname === "/api/validate" && request.method === "POST") {
      try {
        const body = await request.json();
        const key = String(body.key || "").trim();

        if (!key) {
          return Response.json({
            success: false,
            message: "Key wajib diisi"
          }, { status: 400 });
        }

        const result = await env.DB
          .prepare(`
            SELECT id, key, expires_at, active
            FROM keys
            WHERE key = ?
            LIMIT 1
          `)
          .bind(key)
          .first();

        if (!result) {
          return Response.json({
            success: false,
            message: "Key tidak ditemukan"
          }, { status: 404 });
        }

        if (result.active !== 1) {
          return Response.json({
            success: false,
            message: "Key sudah tidak aktif"
          });
        }

        if (Date.now() >= result.expires_at) {
          return Response.json({
            success: false,
            message: "Key sudah expired"
          });
        }

        return Response.json({
          success: true,
          message: "Key valid",
          expires_at: result.expires_at
        });

      } catch (error) {
        return Response.json({
          success: false,
          message: "Request tidak valid"
        }, { status: 400 });
      }
    }

    return Response.json({
      success: false,
      message: "Endpoint tidak ditemukan"
    }, { status: 404 });
  }
};
