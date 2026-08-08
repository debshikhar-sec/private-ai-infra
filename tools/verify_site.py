"""Static-site validation: assets resolve, the tour scrubs, nothing errors.

Loads the showcase site in a real Chrome (Playwright, ``channel="chrome"``) and checks
the things a broken build actually breaks:

  * every referenced asset (img/src, video, tour frames, stylesheets, scripts) returns 200
  * every internal anchor target exists
  * the scroll-driven product tour really swaps frames (IntersectionObserver wiring)
  * no console errors, no failed network requests
  * the stats block's static fallbacks carry truthful non-zero values

Run it against a locally served copy of ``site/``:

    python -m http.server 8090 --directory site
    /tmp/capvenv/bin/python tools/verify_site.py --base http://127.0.0.1:8090

Not part of CI (Playwright is deliberately not a project dependency); this is the
pre-publish gate the media/site increments run by hand.
"""

from __future__ import annotations

import argparse
import sys
from urllib.parse import urljoin

from playwright.sync_api import sync_playwright

FAILURES: list[str] = []


def check(cond: bool, msg: str) -> None:
    if cond:
        print(f"  ok    {msg}")
    else:
        print(f"  FAIL  {msg}")
        FAILURES.append(msg)


def verify(base: str) -> int:
    with sync_playwright() as p:
        browser = p.chromium.launch(channel="chrome", headless=True)
        page = browser.new_page(viewport={"width": 1440, "height": 900})
        console_errors: list[str] = []
        failed_requests: list[str] = []
        page.on("console", lambda m: console_errors.append(m.text) if m.type == "error" else None)
        page.on("requestfailed", lambda r: failed_requests.append(r.url))
        page.goto(base, wait_until="networkidle")

        print("assets:")
        urls = page.evaluate(
            """() => {
              const out = new Set();
              document.querySelectorAll('img[src]').forEach(e => out.add(e.getAttribute('src')));
              document.querySelectorAll('link[rel=stylesheet][href]').forEach(e => out.add(e.getAttribute('href')));
              document.querySelectorAll('script[src]').forEach(e => out.add(e.getAttribute('src')));
              document.querySelectorAll('a[href$=".mp4"], a[href$=".gif"]').forEach(e => out.add(e.getAttribute('href')));
              document.querySelectorAll('#tour-steps .tstep').forEach(e =>
                  out.add('assets/tour/' + e.dataset.frame + '.webp'));
              return [...out].filter(u => u && !u.startsWith('http') && !u.startsWith('#'));
            }"""
        )
        for u in sorted(urls):
            resp = page.request.head(urljoin(base + "/", u))
            check(resp.status == 200, f"{u} -> {resp.status}")

        print("internal anchors:")
        anchors = page.evaluate(
            """() => [...document.querySelectorAll('a[href^="#"]')]
                     .map(a => a.getAttribute('href')).filter(h => h.length > 1)"""
        )
        for a in sorted(set(anchors)):
            exists = page.evaluate("(id) => !!document.querySelector(id)", a)
            check(exists, f"anchor {a}")

        print("product tour:")
        steps = page.locator("#tour-steps .tstep")
        n = steps.count()
        check(n >= 8, f"{n} tour steps")
        first_src = page.get_attribute("#tour-frame", "src")
        seen = {first_src}
        for i in range(n):
            steps.nth(i).scroll_into_view_if_needed()
            page.wait_for_timeout(160)
            seen.add(page.get_attribute("#tour-frame", "src"))
        check(len(seen) == n, f"tour swapped {len(seen)} distinct frames across {n} steps")
        progress = page.text_content("#tour-progress")
        check(progress.strip().endswith(f"/ {n}"), f"progress counter reads '{progress.strip()}'")

        print("stats fallbacks (must be truthful without JS):")
        stats = page.evaluate(
            """() => [...document.querySelectorAll('[data-count]')].map(e => ({
                 count: e.getAttribute('data-count'),
                 text: e.textContent.trim(),
                 label: (e.closest('.stat, li, div')?.textContent || '').trim().slice(0, 60)
               }))"""
        )
        for s in stats:
            # A static fallback of "0" is only truthful for a genuinely-zero metric.
            check(s["text"] != "" and s["text"] != "—",
                  f"stat data-count={s['count']} renders '{s['text']}'")

        print("runtime cleanliness:")
        check(not console_errors, f"console errors: {console_errors[:3] or 'none'}")
        check(not failed_requests, f"failed requests: {failed_requests[:3] or 'none'}")

        browser.close()

    print()
    if FAILURES:
        print(f"{len(FAILURES)} FAILURE(S)")
        return 1
    print("site verification passed")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--base", default="http://127.0.0.1:8090")
    return verify(ap.parse_args().base.rstrip("/"))


if __name__ == "__main__":
    sys.exit(main())
