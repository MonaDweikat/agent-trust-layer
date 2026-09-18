import { SCENARIOS, type ScenarioResult, type Step } from "./scenarios.js";
import type { TaskEvaluation } from "../../src/agents/index.js";

const nav = document.getElementById("scenario-nav")!;
const output = document.getElementById("output")!;

function renderEvaluation(requester: string, evaluation: TaskEvaluation, note?: string): HTMLElement {
  const card = document.createElement("div");
  card.className = `decision-card ${evaluation.decision}`;

  const heading = document.createElement("p");
  heading.className = "decision-heading";
  heading.textContent =
    evaluation.decision === "accept"
      ? `✅ ACCEPT — task request from ${requester}`
      : `❌ REFUSE — task request from ${requester}`;
  card.appendChild(heading);

  if (!evaluation.holderValid) {
    const reason = document.createElement("p");
    reason.className = "decision-note";
    reason.textContent = evaluation.holderReason ?? "presentation signature invalid";
    card.appendChild(reason);
  }

  if (note) {
    const noteEl = document.createElement("p");
    noteEl.className = "decision-note";
    noteEl.textContent = note;
    card.appendChild(noteEl);
  }

  const list = document.createElement("ul");
  list.className = "rule-list";
  for (const rule of evaluation.trace) {
    const li = document.createElement("li");
    li.className = rule.passed ? "pass" : "fail";
    const mark = document.createElement("span");
    mark.className = "rule-mark";
    mark.textContent = rule.passed ? "✓" : "✗";
    const text = document.createElement("span");
    text.textContent = rule.description;
    li.appendChild(mark);
    li.appendChild(text);
    list.appendChild(li);
  }
  card.appendChild(list);

  return card;
}

function renderStep(step: Step): HTMLElement {
  if (step.kind === "text") {
    const p = document.createElement("p");
    p.className = "step-text";
    p.textContent = step.text;
    return p;
  }
  return renderEvaluation(step.requester, step.evaluation, step.note);
}

function renderResult(result: ScenarioResult): void {
  output.innerHTML = "";

  const title = document.createElement("h2");
  title.className = "scenario-title";
  title.textContent = result.title;
  output.appendChild(title);

  const summary = document.createElement("p");
  summary.className = "scenario-summary";
  summary.textContent = result.summary;
  output.appendChild(summary);

  for (const step of result.steps) {
    output.appendChild(renderStep(step));
  }
}

function setLoading(): void {
  output.innerHTML = '<p class="loading">Generating keys, signing credentials, verifying…</p>';
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
      renderResult(result);
    } catch (err) {
      output.innerHTML = `<p class="loading">Error running scenario: ${(err as Error).message}</p>`;
    } finally {
      allButtons.forEach((b) => ((b as HTMLButtonElement).disabled = false));
    }
  });
  nav.appendChild(button);
}
