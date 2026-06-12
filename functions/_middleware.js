// Shared username/password gate (HTTP Basic Auth) for this Cloudflare Pages site.
// Credentials come from the Pages project's environment variables BASIC_USER / BASIC_PASS.
// Fails CLOSED: if the secret isn't configured, nobody gets in.
export async function onRequest(context) {
  const { request, env, next } = context;
  const USER = env.BASIC_USER;
  const PASS = env.BASIC_PASS;

  if (!USER || !PASS) {
    return new Response("Gate not configured.", {
      status: 503,
      headers: { "X-Robots-Tag": "noindex, nofollow" },
    });
  }

  const expected = "Basic " + btoa(USER + ":" + PASS);
  const provided = request.headers.get("Authorization") || "";

  if (provided !== expected) {
    return new Response("Authentication required.", {
      status: 401,
      headers: {
        "WWW-Authenticate": 'Basic realm="Private — Growth Spike", charset="UTF-8"',
        "X-Robots-Tag": "noindex, nofollow",
      },
    });
  }

  // Authenticated: serve the static asset, keep the noindex header.
  const res = await next();
  const out = new Response(res.body, res);
  out.headers.set("X-Robots-Tag", "noindex, nofollow");
  return out;
}
