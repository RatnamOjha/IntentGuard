"use client";

import { scenarios, type ScenarioKey } from "../lib/scenarios";
import styles from "./ScenarioList.module.css";

export function ScenarioList({
  selected,
  onSelect,
  disabled,
}: {
  selected: ScenarioKey;
  onSelect: (key: ScenarioKey) => void;
  disabled: boolean;
}) {
  return (
    <div className={styles.list} role="radiogroup" aria-label="Request to evaluate">
      {(Object.keys(scenarios) as ScenarioKey[]).map((key) => {
        const scenario = scenarios[key];
        const active = key === selected;
        return (
          <button
            aria-checked={active}
            className={active ? `${styles.item} ${styles.active}` : styles.item}
            disabled={disabled}
            key={key}
            onClick={() => onSelect(key)}
            role="radio"
            type="button"
          >
            <span className={styles.top}>
              <span className={styles.title}>{scenario.title}</span>
              <span
                className={
                  scenario.expect === "Allowed"
                    ? `${styles.expect} ${styles.pass}`
                    : scenario.expect === "Human review"
                      ? `${styles.expect} ${styles.hold}`
                      : `${styles.expect} ${styles.stop}`
                }
              >
                {scenario.expect}
              </span>
            </span>
            <span className={styles.blurb}>{scenario.blurb}</span>
          </button>
        );
      })}
    </div>
  );
}
