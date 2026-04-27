#!/usr/bin/env janet
#
# PyGrove Chain — public landing page.
#
# Written in Janet (https://janet-lang.org) — a small Lisp dialect that
# embeds in C and ships with a fiber-based net stdlib in core. This is
# the most obscure language I could find that still meshes with the
# project: Bitcoin Script is Forth, PyGrove inherits Bitcoin's skeleton,
# and a Lisp serving the landing page is the same kind of family-tree
# joke. ~80 lines, zero dependencies beyond Janet itself.
#
# The server listens on :8080 and, on every page load, opens a TCP
# connection to the local node on :8545, posts a JSON-RPC `get_info`,
# and embeds chain_id / height / tip_hash directly into the HTML it
# returns. No client-side fetch, no CORS dance — pure server-side
# rendering against the node sitting on the same VPS.

(def NODE-HOST (or (os/getenv "PYG_NODE_HOST") "127.0.0.1"))
(def NODE-PORT (or (os/getenv "PYG_NODE_PORT") "8545"))
(def BIND-HOST "0.0.0.0")
(def BIND-PORT (or (os/getenv "PORT") "8080"))

# ---- node RPC client --------------------------------------------------------

(defn rpc-call [method]
  "POST a JSON-RPC request, return the response body as a string. On
   any failure, return a synthetic error JSON so the renderer always
   has something shaped like a result block to extract from."
  (try
    (let [s (net/connect NODE-HOST NODE-PORT)
          payload (string "{\"method\":\"" method "\"}")
          hdr (string
                 "POST /rpc HTTP/1.1\r\n"
                 "Host: " NODE-HOST ":" NODE-PORT "\r\n"
                 "Content-Type: application/json\r\n"
                 "Content-Length: " (length payload) "\r\n"
                 "Connection: close\r\n\r\n")]
      (:write s (string hdr payload))
      (def buf @"")
      (forever
        (def chunk (:read s 4096))
        (when (or (nil? chunk) (zero? (length chunk))) (break))
        (buffer/push-string buf chunk))
      (:close s)
      # Strip the HTTP headers — body starts after the first \r\n\r\n.
      (def s (string buf))
      (let [i (string/find "\r\n\r\n" s)]
        (if i (string/slice s (+ i 4)) "{}")))
    ([err]
      (eprint "rpc-call: " err)
      (string
        "{\"result\":{\"chain_id\":\"node-unreachable\","
        "\"height\":0,"
        "\"tip_hash\":\"" err "\"}}"))))

(defn extract [body key default]
  "Cheap JSON extraction. Finds \"key\":value, handles strings and
   numbers. We don't pull a JSON parser dep for one POST per request."
  (let [needle (string "\"" key "\":")
        i (string/find needle body)]
    (if (nil? i)
      default
      (let [start (+ i (length needle))
            rest (string/slice body start)]
        (if (and (> (length rest) 0) (= (rest 0) (chr "\"")))
          # quoted string
          (let [end (string/find "\"" rest 1)]
            (if end (string/slice rest 1 end) default))
          # number — read until , or }
          (let [c (or (string/find "," rest) (length rest))
                b (or (string/find "}" rest) (length rest))
                end (min c b)]
            (string/slice rest 0 end)))))))

# ---- HTML template ----------------------------------------------------------

(def page-template
  ``<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8" />
<title>PyGrove Chain — testnet</title>
<meta name="viewport" content="width=device-width,initial-scale=1" />
<meta name="description" content="A self-reflective, crypto-agile, stability-seeking proof-of-work blockchain." />
<style>
:root{--bg:#0b0d10;--bg2:#11151a;--fg:#e8f0ff;--dim:#9aa6b2;--line:#1e252d;--accent:#7cc4ff;--ok:#7cffa4;--warn:#ffb95c}
*{box-sizing:border-box}
body{margin:0;font:14px/1.6 ui-monospace,Menlo,Consolas,monospace;background:var(--bg);color:var(--fg);min-height:100vh}
.wrap{max-width:880px;margin:0 auto;padding:64px 28px 96px}
h1{margin:0 0 4px 0;font-size:42px;letter-spacing:-0.5px;font-weight:600}
h1 .accent{color:var(--accent)}
.tnet{display:inline-block;padding:3px 10px;background:var(--bg2);border:1px solid var(--warn);color:var(--warn);border-radius:4px;font-size:11px;margin-left:10px;vertical-align:middle;letter-spacing:1px}
.tag{color:var(--dim);font-size:14px;margin-bottom:36px}
.countdown{background:linear-gradient(135deg,#1a1f2a 0%,#11151a 100%);border:1px solid var(--accent);border-radius:8px;padding:22px 24px;margin:28px 0}
.countdown .lbl{color:var(--accent);font-size:11px;text-transform:uppercase;letter-spacing:1px;font-weight:600}
.countdown .clock{font-size:32px;color:var(--fg);margin:10px 0 4px 0;font-variant-numeric:tabular-nums}
.countdown .when{color:var(--dim);font-size:12px}
.live{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:14px;margin:28px 0}
.cell{background:var(--bg2);border:1px solid var(--line);border-radius:8px;padding:14px 16px}
.cell .lbl{color:var(--dim);font-size:11px;text-transform:uppercase;letter-spacing:0.5px}
.cell .val{font-size:16px;margin-top:6px;word-break:break-all;color:var(--fg)}
.cell .val.tip{font-size:11px;color:var(--accent);line-height:1.4}
section{margin:38px 0}
section h2{margin:0 0 12px 0;font-size:13px;color:var(--dim);text-transform:uppercase;letter-spacing:0.5px;font-weight:500}
section p{margin:0 0 14px 0;color:#cfd6df}
.links{display:flex;gap:12px;flex-wrap:wrap;margin-top:18px}
.btn{background:var(--bg2);border:1px solid var(--line);color:var(--fg);text-decoration:none;padding:10px 16px;border-radius:6px;font-size:13px;transition:border-color 0.15s,color 0.15s}
.btn:hover{border-color:var(--accent);color:var(--accent)}
.btn.primary{background:var(--accent);color:var(--bg);border-color:var(--accent);font-weight:600}
.btn.primary:hover{background:#5fb3f0;color:var(--bg);border-color:#5fb3f0}
footer{margin-top:64px;padding-top:24px;border-top:1px solid var(--line);color:var(--dim);font-size:11px;line-height:1.7}
footer a{color:var(--dim)}
footer a:hover{color:var(--accent)}
.pill{display:inline-block;padding:2px 10px;background:var(--bg2);border:1px solid var(--line);border-radius:4px;color:var(--ok);font-size:11px;margin-left:6px}
</style>
</head>
<body>
<div class="wrap">

<h1>Py<span class="accent">Grove</span> Chain<span class="tnet">TESTNET</span></h1>
<div class="tag">A self-reflective, crypto-agile, stability-seeking proof-of-work blockchain.</div>

{COUNTDOWN_BLOCK}

<section>
<p>PyGrove inherits Bitcoin's economic skeleton — 10-minute block target, 2,016-block retargets, 210,000-block halving epochs, 21,000,000-coin hard cap — and adds three layers on top: a two-bellow accordion that lets issuance breathe with hashrate and adoption, a reflection subtree that records the chain's own statistics on-chain, and a crypto-agility layer that makes algorithm replacement a routine governance transaction.</p>
<p>Falcon-512 hot signatures, SLH-DSA-128s cold governance keys, blake3-XOF-512 block hashing, SHAKE256 with per-subtree domain tags. The chain is its own basket — an ETF of one. Design horizon:<span class="pill">127 years</span></p>
</section>

<section>
<h2>Live tip</h2>
<div class="live">
  <div class="cell"><div class="lbl">Chain ID</div><div class="val">{CHAIN_ID}</div></div>
  <div class="cell"><div class="lbl">Block height</div><div class="val">{HEIGHT}</div></div>
  <div class="cell" style="grid-column:span 2"><div class="lbl">Tip hash</div><div class="val tip">{TIP}</div></div>
</div>
</section>

<section>
<h2>Get started</h2>
<div class="links">
<a class="btn primary" href="http://66.42.93.85:8545/">Open the explorer →</a>
<a class="btn" href="https://github.com/xjqcj357/pygrove-chain">GitHub</a>
<a class="btn" href="https://github.com/xjqcj357/pygrove-chain/blob/main/docs/whitepaper.md">Whitepaper</a>
<a class="btn" href="https://github.com/xjqcj357/pygrove-chain/actions">Releases</a>
</div>
</section>

<footer>
Served by ~80 lines of <a href="https://janet-lang.org">Janet</a> — a Lisp dialect almost no one's heard of, talking to the node container next door over JSON-RPC. Source: <a href="https://github.com/xjqcj357/pygrove-chain/tree/main/web">/web/site.janet</a>.
</footer>

</div>
</body>
</html>``)

# ---- request handler --------------------------------------------------------

(defn fmt-countdown [secs]
  "Pretty-print a positive integer second count as a T-Xd Yh Zm Ws string."
  (let [d (div secs 86400)
        h (mod (div secs 3600) 24)
        m (mod (div secs 60) 60)
        s (mod secs 60)]
    (cond
      (> d 0) (string "T-" d "d " h "h " m "m " s "s")
      (> h 0) (string "T-" h "h " m "m " s "s")
      (> m 0) (string "T-" m "m " s "s")
      (string "T-" s "s"))))

(defn countdown-block [body]
  "Render the pre-genesis lockout banner if now < genesis_time_ms. The node
   serves genesis_offset_ms in get_info — negative means pre-genesis."
  (let [offset-str (extract body "genesis_offset_ms" "0")
        gtime-str (extract body "genesis_time_ms" "0")
        offset (or (scan-number offset-str) 0)
        gtime (or (scan-number gtime-str) 0)]
    (if (< offset 0)
      (let [secs-until (math/floor (/ (- 0 offset) 1000))]
        (string
          "<div class=\"countdown\">"
          "<div class=\"lbl\">PRE-GENESIS &middot; fair launch lockout</div>"
          "<div class=\"clock\">" (fmt-countdown secs-until) "</div>"
          "<div class=\"when\">Block 1 submission opens at unix_ms=" gtime
          ". The chain stays at height 0 until then. No premine.</div>"
          "</div>"))
      "")))

(defn render-page []
  "Server-side render: fetch get_info from the node, splice into HTML."
  (let [body (rpc-call "get_info")
        chain-id (extract body "chain_id" "—")
        height (extract body "height" "—")
        tip (extract body "tip_hash" "—")
        countdown (countdown-block body)]
    # ->> threads the value through as the LAST arg of each form.
    # Janet's `string/replace` signature is (string/replace patt subst str),
    # so the source string belongs in the trailing position.
    (->> page-template
         (string/replace "{CHAIN_ID}" chain-id)
         (string/replace "{HEIGHT}" height)
         (string/replace "{TIP}" tip)
         (string/replace "{COUNTDOWN_BLOCK}" countdown))))

(defn http-respond [stream html]
  (let [body (string html)
        head (string
               "HTTP/1.1 200 OK\r\n"
               "Content-Type: text/html; charset=utf-8\r\n"
               "Content-Length: " (length body) "\r\n"
               "Cache-Control: no-store\r\n"
               "Connection: close\r\n\r\n")]
    (:write stream head)
    (:write stream body)))

(defn handler [stream]
  (try
    (do
      # Drain the request line/headers — we only serve one page so we
      # don't bother routing.
      (:read stream 4096)
      (http-respond stream (render-page)))
    ([err] (eprint "handler error: " err)))
  (try (:close stream) ([_] nil)))

# ---- main loop --------------------------------------------------------------

(net/server BIND-HOST BIND-PORT handler)
(print "pygrove-web: listening on " BIND-HOST ":" BIND-PORT
       "  -> rpc " NODE-HOST ":" NODE-PORT)
(forever (ev/sleep 60))
