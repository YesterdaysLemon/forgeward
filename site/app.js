"use strict";

const FORGEWARD_CONFIG = Object.freeze({
  githubUrl: "https://github.com/YesterdaysLemon/forgeward",
});

function hydrateRepositoryLinks() {
  const { githubUrl } = FORGEWARD_CONFIG;

  document.querySelectorAll("[data-github-link]").forEach((link) => {
    link.href = githubUrl;
  });

  document.querySelectorAll("[data-github-clone]").forEach((line) => {
    line.textContent = `git clone ${githubUrl}.git`;
  });

  document.querySelectorAll("[data-github-display]").forEach((label) => {
    try {
      const repository = new URL(githubUrl);
      label.textContent = `${repository.hostname}${repository.pathname}`;
    } catch {
      label.textContent = "Open the ForgeWard repository";
    }
  });
}

function setupMobileNavigation() {
  const toggle = document.querySelector("#menu-toggle");
  const navigation = document.querySelector("#site-nav");

  if (!toggle || !navigation) return;

  const setOpen = (open) => {
    toggle.setAttribute("aria-expanded", String(open));
    navigation.classList.toggle("is-open", open);
  };

  toggle.addEventListener("click", () => {
    setOpen(toggle.getAttribute("aria-expanded") !== "true");
  });

  navigation.addEventListener("click", (event) => {
    if (event.target.closest("a")) setOpen(false);
  });

  document.addEventListener("click", (event) => {
    if (!navigation.contains(event.target) && !toggle.contains(event.target)) {
      setOpen(false);
    }
  });

  document.addEventListener("keydown", (event) => {
    if (event.key === "Escape" && toggle.getAttribute("aria-expanded") === "true") {
      setOpen(false);
      toggle.focus();
    }
  });

  window.addEventListener("resize", () => {
    if (window.innerWidth > 900) setOpen(false);
  });
}

function setupRoleTabs() {
  const tabList = document.querySelector('[role="tablist"]');
  if (!tabList) return;

  const tabs = Array.from(tabList.querySelectorAll('[role="tab"]'));

  const activateTab = (selectedTab, moveFocus = false) => {
    tabs.forEach((tab) => {
      const selected = tab === selectedTab;
      const panel = document.getElementById(tab.getAttribute("aria-controls"));

      tab.setAttribute("aria-selected", String(selected));
      tab.tabIndex = selected ? 0 : -1;
      if (panel) panel.hidden = !selected;
    });

    if (moveFocus) selectedTab.focus();
  };

  tabs.forEach((tab, index) => {
    tab.addEventListener("click", () => activateTab(tab));
    tab.addEventListener("keydown", (event) => {
      let nextIndex = null;

      if (event.key === "ArrowRight" || event.key === "ArrowDown") {
        nextIndex = (index + 1) % tabs.length;
      } else if (event.key === "ArrowLeft" || event.key === "ArrowUp") {
        nextIndex = (index - 1 + tabs.length) % tabs.length;
      } else if (event.key === "Home") {
        nextIndex = 0;
      } else if (event.key === "End") {
        nextIndex = tabs.length - 1;
      }

      if (nextIndex !== null) {
        event.preventDefault();
        activateTab(tabs[nextIndex], true);
      }
    });
  });
}

function fallbackCopy(text) {
  const textarea = document.createElement("textarea");
  textarea.value = text;
  textarea.setAttribute("readonly", "");
  textarea.className = "clipboard-helper";
  document.body.appendChild(textarea);
  textarea.select();

  const copied = document.execCommand("copy");
  textarea.remove();

  if (!copied) throw new Error("Copy command was unavailable");
}

async function copyText(text) {
  if (navigator.clipboard && window.isSecureContext) {
    await navigator.clipboard.writeText(text);
    return;
  }

  fallbackCopy(text);
}

function setupCopyButtons() {
  const status = document.querySelector("#copy-status");

  document.querySelectorAll("[data-copy-target]").forEach((button) => {
    const originalLabel = button.querySelector(".copy-label")?.textContent || "Copy";
    let resetTimer;

    button.addEventListener("click", async () => {
      const target = document.getElementById(button.dataset.copyTarget);
      const label = button.querySelector(".copy-label");
      if (!target || !label) return;

      window.clearTimeout(resetTimer);

      try {
        await copyText(target.innerText.trim());
        label.textContent = "Copied ✓";
        if (status) status.textContent = `${button.dataset.copyTarget === "quickstart-code" ? "Quick start" : "Configuration"} copied to clipboard.`;
      } catch {
        label.textContent = "Select text";
        if (status) status.textContent = "Clipboard access was unavailable. Select the code and copy it manually.";
      }

      resetTimer = window.setTimeout(() => {
        label.textContent = originalLabel;
      }, 2200);
    });
  });
}

function setupHeaderState() {
  const header = document.querySelector(".site-header");
  if (!header) return;

  const updateHeader = () => header.classList.toggle("is-scrolled", window.scrollY > 8);
  updateHeader();
  window.addEventListener("scroll", updateHeader, { passive: true });
}

function setupRevealMotion() {
  const reducedMotion = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
  const elements = document.querySelectorAll(".reveal");

  if (reducedMotion || !("IntersectionObserver" in window)) {
    elements.forEach((element) => element.classList.add("is-visible"));
    return;
  }

  document.documentElement.classList.add("motion-enhanced");

  const observer = new IntersectionObserver(
    (entries) => {
      entries.forEach((entry) => {
        if (!entry.isIntersecting) return;
        entry.target.classList.add("is-visible");
        observer.unobserve(entry.target);
      });
    },
    { rootMargin: "0px 0px -8%", threshold: 0.08 },
  );

  elements.forEach((element) => observer.observe(element));
}

function setCurrentYear() {
  const year = document.querySelector("#current-year");
  if (year) year.textContent = String(new Date().getFullYear());
}

hydrateRepositoryLinks();
setupMobileNavigation();
setupRoleTabs();
setupCopyButtons();
setupHeaderState();
setupRevealMotion();
setCurrentYear();
