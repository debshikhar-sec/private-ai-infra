// private-ai-infra showcase — progressive enhancement only. The page is fully
// readable with JS disabled; this adds polish (diagrams, count-up, nav state).

/* ---- feature detection: scroll-driven animations ---- */
const supportsScrollTimeline = CSS && CSS.supports && CSS.supports("animation-timeline: view()");
if (!supportsScrollTimeline) {
  document.documentElement.classList.add("no-scroll-timeline");
  const io = new IntersectionObserver(
    (entries) => entries.forEach((e) => { if (e.isIntersecting) { e.target.classList.add("in"); io.unobserve(e.target); } }),
    { threshold: 0.12 }
  );
  document.querySelectorAll(".reveal").forEach((el) => io.observe(el));
}

/* ---- sticky nav shadow ---- */
const nav = document.querySelector(".nav");
const onScroll = () => nav && nav.classList.toggle("scrolled", window.scrollY > 8);
addEventListener("scroll", onScroll, { passive: true });
onScroll();

/* ---- count-up stats ---- */
const reduceMotion = matchMedia("(prefers-reduced-motion: reduce)").matches;
function countUp(el) {
  const target = parseFloat(el.dataset.count);
  const suffix = el.dataset.suffix || "";
  const decimals = (el.dataset.count.split(".")[1] || "").length;
  if (reduceMotion) { el.textContent = target.toFixed(decimals) + suffix; return; }
  const dur = 1400; const t0 = performance.now();
  const tick = (t) => {
    const p = Math.min((t - t0) / dur, 1);
    const eased = 1 - Math.pow(1 - p, 3);
    el.textContent = (target * eased).toFixed(decimals) + suffix;
    if (p < 1) requestAnimationFrame(tick);
  };
  requestAnimationFrame(tick);
}
const statObs = new IntersectionObserver((entries) => {
  entries.forEach((e) => { if (e.isIntersecting) { countUp(e.target); statObs.unobserve(e.target); } });
}, { threshold: 0.6 });
document.querySelectorAll("[data-count]").forEach((el) => statObs.observe(el));

/* ---- footer year ---- */
const y = document.getElementById("year");
if (y) y.textContent = new Date().getFullYear();

// Diagrams are pre-rendered SVG (control plane) + hand-built CSS (gauntlet) —
// no runtime diagram dependency, so nothing can fail to load or flash.

/* ---- product tour: scroll-driven frame scrubbing ---- */
const tourImg = document.getElementById("tour-frame");
if (tourImg) {
  const steps = [...document.querySelectorAll("#tour-steps .tstep")];
  const actor = document.getElementById("tour-actor");
  const progress = document.getElementById("tour-progress");

  // Preload every frame once the tour approaches the viewport, so scrubbing never flashes.
  const preload = () => steps.forEach((s) => { new Image().src = `assets/tour/${s.dataset.frame}.webp`; });
  new IntersectionObserver((entries, obs) => {
    if (entries.some((e) => e.isIntersecting)) { preload(); obs.disconnect(); }
  }, { rootMargin: "600px" }).observe(tourImg);

  const activate = (step) => {
    const i = steps.indexOf(step);
    if (i < 0 || !step.dataset.frame) return;
    tourImg.src = `assets/tour/${step.dataset.frame}.webp`;
    steps.forEach((s) => s.classList.toggle("active", s === step));
    if (actor) actor.innerHTML = "connected as <b>" + step.dataset.actor + "</b>";
    if (progress) progress.textContent = `${i + 1} / ${steps.length}`;
  };

  // A step becomes active when it crosses the middle band of the viewport.
  const stepObs = new IntersectionObserver((entries) => {
    entries.forEach((e) => { if (e.isIntersecting) activate(e.target); });
  }, { rootMargin: "-42% 0px -42% 0px" });
  steps.forEach((s) => stepObs.observe(s));
}
