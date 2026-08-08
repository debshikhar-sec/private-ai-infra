"""Product-walkthrough capture rig — real frames from a really running plane.

Drives the Governed Chat Console and the Governance Console in a real Chrome (via
Playwright, ``channel="chrome"`` — no bundled browser download) against a LIVE gateway
and captures the numbered walkthrough frames the README / showcase site use. Every frame
is a screenshot of the actual product driven over the actual wire; nothing is mocked or
composited.

This rig is a development tool, not part of CI (the deterministic scenario proof lives in
``tests/unit/test_chat_scenarios.py``). Playwright is intentionally NOT a project
dependency — run it from any throwaway environment:

    python -m venv /tmp/capvenv && /tmp/capvenv/bin/pip install playwright
    scripts/demo_durable.sh --port 8099        # hardened demo (ephemeral keys), or
    private-ai-gateway demo --port 8099        # the ordinary zero-config demo
    /tmp/capvenv/bin/python tools/capture_walkthrough.py \
        --base http://127.0.0.1:8099 --owner-token <printed by the demo> \
        --out /tmp/tour-frames

Assembly into site/README media (from the output directory):

    ffmpeg -framerate 1/2.6 -i %02d-*.png ...   # see site/assets/tour/README note

Determinism: every step waits on rendered text/selectors (no fixed sleeps beyond
Playwright's own waiting), animations are disabled, and the viewport is pinned.
Screenshots never contain key material: tokens are typed only into password inputs.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from playwright.sync_api import Page, sync_playwright

VIEWPORT = {"width": 1440, "height": 900}
_FREEZE_CSS = (
    "html{scroll-behavior:auto!important}"
    "*,*::before,*::after{animation:none!important;transition:none!important}"
)

GOAL = "Apply the reviewed dependency fix under governed delegation and verify it"
DENY_GOAL = "Rotate the sandbox service credentials and verify the change"


def _frame(page: Page, out: Path, name: str) -> None:
    path = out / f"{name}.png"
    page.screenshot(path=str(path))
    print(f"  captured {path.name}")


def _open(page: Page, url: str) -> None:
    page.goto(url, wait_until="networkidle")
    page.add_style_tag(content=_FREEZE_CSS)


def _chat_plan(page: Page, goal: str) -> None:
    page.fill("#goal", goal)
    page.click("#send")
    page.wait_for_selector("text=discovers 'opencode' via its card")


def capture(base: str, hermes_token: str, owner_token: str, out: Path) -> int:
    out.mkdir(parents=True, exist_ok=True)
    with sync_playwright() as p:
        browser = p.chromium.launch(channel="chrome", headless=True)
        # bypass_csp affects only this capture context so Playwright's own injected
        # utilities (waits, scrolls) can run; the product's CSP is verified separately in
        # tests/unit/test_chat_scenarios.py and is untouched by this rig.
        context = browser.new_context(
            viewport=VIEWPORT, device_scale_factor=2, bypass_csp=True
        )
        page = context.new_page()

        # --- Act I: the Governed Chat (operate) --------------------------------------
        _open(page, f"{base}/chat")
        page.fill("#token", hermes_token)
        page.fill("#goal", GOAL)
        _frame(page, out, "01-chat-shell")

        page.click("#send")
        page.wait_for_selector("text=discovers 'opencode' via its card")
        _frame(page, out, "02-plan-and-frozen-proposal")

        # Hermes cannot approve its own plan: the planner token in the owner box is a
        # REAL 403 owner_required on the wire — and the proposal card survives to retry.
        card = page.locator(".card").last
        card.locator("input[type=password]").fill(hermes_token)
        card.get_by_role("button", name="Approve & apply ▸").click()
        page.wait_for_selector("text=owner_required")
        # Show the refusal itself, not just the card that triggered it.
        page.evaluate("window.scrollTo(0, document.body.scrollHeight)")
        _frame(page, out, "03-self-approval-refused")

        card.locator("input[type=password]").fill(owner_token)
        card.get_by_role("button", name="Approve & apply ▸").click()
        page.wait_for_selector("text=Signed evidence lineage")
        page.get_by_text(
            "approves the sandbox apply (owner-gated, hash-bound)"
        ).scroll_into_view_if_needed()
        page.evaluate("window.scrollBy(0, -120)")
        _frame(page, out, "04-owner-approves-sandbox-applies")

        page.evaluate("window.scrollTo(0, document.body.scrollHeight)")
        _frame(page, out, "05-verified-with-evidence-lineage")

        # A second run where authority is withheld: the governed refusal, on the wire.
        _chat_plan(page, DENY_GOAL)
        page.locator(".card:not(.stale)").last.get_by_role(
            "button", name="Deny (show refusal)"
        ).click()
        page.wait_for_selector("text=nothing was applied — authority was not granted")
        page.evaluate("window.scrollTo(0, document.body.scrollHeight)")
        _frame(page, out, "06-authority-withheld-refused")

        page.click("#probe")
        page.wait_for_selector("text=Every abuse was refused")
        page.evaluate("window.scrollTo(0, document.body.scrollHeight)")
        _frame(page, out, "07-boundary-probe")

        # --- Act II: the Governance Console (inspect) --------------------------------
        _open(page, f"{base}/console")
        page.fill("#token", "demo-auditor")
        page.click("#connect")
        page.wait_for_function(
            "document.getElementById('s-allow').textContent.trim() !== '—'"
        )
        _frame(page, out, "08-console-overview")

        page.click("button.nv[data-pane=audit]")
        page.wait_for_selector("#feed .row, #feed div:not(.empty)")
        _frame(page, out, "09-live-audit")

        # A live over-authority probe from the console: research-copilot declares L6.
        page.click("#disconnect")
        page.fill("#token", "demo-research-copilot")
        page.click("#connect")
        page.wait_for_function(
            "document.getElementById('who-chip-t').textContent.includes('research')"
        )
        page.click("button.nv[data-pane=probe]")
        page.select_option("#p-level", "6")
        page.click("#p-send")
        page.wait_for_selector("#p-out:not(.hidden)")
        _frame(page, out, "10-probe-lab-denial")

        page.click("button.nv[data-pane=tools]")
        page.wait_for_selector("#pane-tools.active")
        _frame(page, out, "11-tools-floors")

        # --- Coda: the thesis --------------------------------------------------------
        _open(page, f"{base}/chat")
        page.fill("#token", hermes_token)
        _chat_plan(page, GOAL)
        live = page.locator(".card:not(.stale)").last
        live.locator("input[type=password]").fill(owner_token)
        live.get_by_role("button", name="Approve & apply ▸").click()
        page.wait_for_selector("text=Signed evidence lineage")
        page.evaluate("window.scrollTo(0, document.body.scrollHeight)")
        _frame(page, out, "12-capability-not-authority")

        browser.close()
    print(f"{len(list(out.glob('*.png')))} frames in {out}")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--base", default="http://127.0.0.1:8099")
    ap.add_argument("--hermes-token", default="demo-hermes")
    ap.add_argument("--owner-token", required=True,
                    help="the break-glass token the demo printed at startup")
    ap.add_argument("--out", required=True, type=Path)
    args = ap.parse_args()
    return capture(args.base, args.hermes_token, args.owner_token, args.out)


if __name__ == "__main__":
    sys.exit(main())
