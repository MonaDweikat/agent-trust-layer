import { SCENARIOS, type Step } from "./scenarios.js";

const nav = document.getElementById("scenario-nav")!;
const output = document.getElementById("output")!;

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function renderStep(step: Step): HTMLElement {
  const row = document.createElement("div");
  row.className = `step step-${step.kind}`;

  if (step.kind === "narrate") {
    row.innerHTML = `<p class="narrate-text">${step.text}</p>`;
    return row;
  }

  if (step.kind === "issue") {
    row.innerHTML = `
      <span class="actor actor-issuer">${step.from}</span>
      <span class="arrow">issues ⟶</span>
      <span class="actor actor-recipient">${step.to}</span>
      <span class="payload">${step.label}</span>
    `;
    return row;
  }

  if (step.kind === "message") {
    row.innerHTML = `
      <span class="actor actor-sender">${step.from}</span>
      <span class="arrow arrow-message">──────▶</span>
      <span class="actor actor-recipient">${step.to}</span>
      <span class="payload">${step.label}</span>
    `;
    return row;
  }

  if (step.kind === "check") {
    row.classList.add(step.passed ? "check-pass" : "check-fail");
    const mark = step.passed ? "✓" : "✗";
    row.innerHTML = `
      <span class="check-mark">${mark}</span>
      <span class="check-actor">${step.actor} checks:</span>
      <span class="check-label">${step.label}</span>
      ${step.detail ? `<span class="check-detail">${step.detail}</span>` : ""}
    `;
    return row;
  }

  // decision
  const heading = step.accepted
    ? `✅ ACCEPT — ${step.requester}'s request is granted`
    : `❌ REFUSE — ${step.requester}'s request is denied`;
  row.classList.add(step.accepted ? "decision-accept" : "decision-refuse");
  row.innerHTML = `<p class="decision-heading">${heading}</p>`;
  return row;
}

async function playScenario(steps: Step[]): Promise<void> {
  output.innerHTML = "";
  for (const step of steps) {
    const el = renderStep(step);
    el.classList.add("enter");
    output.appendChild(el);
    output.scrollTop = output.scrollHeight;
    // Force layout so the enter transition actually plays, then trigger it.
    requestAnimationFrame(() => el.classList.add("enter-active"));
    const delay = step.kind === "decision" ? 250 : step.kind === "narrate" ? 500 : 350;
    await sleep(delay);
  }
}

function setLoading(): void {
  output.innerHTML = '<p class="loading">Generating keys, signing credentials, computing…</p>';
}

for (const scenario of SCENARIOS) {
  const button = document.createElement("button");
  button.textContent = scenario.label;
  button.addEventListener("click", async () => {
    for (const b of nav.querySelectorAll("button")) b.classList.remove("active");
    button.classList.add("active");

    const allButtons = nav.querySelectorAll("button");
    allButtons.forEach((b) => ((b as HTMLButtonElement).disabled = true));
    setLoading();

    try {
      const result = await scenario.run();
      await sleep(150);
      const header = document.createElement("div");
      header.className = "scenario-header";
      header.innerHTML = `<h2 class="scenario-title">${result.title}</h2><p class="scenario-summary">${result.summary}</p>`;
      output.innerHTML = "";
      output.appendChild(header);
      await playScenario(result.steps);
    } catch (err) {
      output.innerHTML = `<p class="loading">Error running scenario: ${(err as Error).message}</p>`;
    } finally {
      allButtons.forEach((b) => ((b as HTMLButtonElement).disabled = false));
    }
  });
  nav.appendChild(button);
}
