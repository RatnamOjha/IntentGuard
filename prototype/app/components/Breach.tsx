import { Money } from "./Money";
import styles from "./Breach.module.css";

/**
 * The two bars that carry the whole argument: what policy allowed, and what
 * was asked for. Widths are proportional so the gap is visible before the
 * numbers are read.
 */
export function Breach({
  limit,
  actual,
  limitLabel = "allowed",
  actualLabel = "requested",
}: {
  limit: number;
  actual: number;
  limitLabel?: string;
  actualLabel?: string;
}) {
  const span = Math.max(limit, actual, 1);
  const over = limit > 0 ? actual / limit : null;
  return (
    <div className={styles.wrap}>
      <div className={styles.row}>
        <span className={styles.label}>{limitLabel}</span>
        <div className={styles.track}>
          <span
            className={styles.barAllowed}
            style={{ width: `${Math.max((limit / span) * 100, 1.5)}%` }}
          />
        </div>
        <Money amount={limit} size="sm" tone="pass" />
      </div>
      <div className={styles.row}>
        <span className={styles.label}>{actualLabel}</span>
        <div className={styles.track}>
          <span
            className={styles.barAsked}
            style={{ width: `${Math.max((actual / span) * 100, 1.5)}%` }}
          />
        </div>
        <Money amount={actual} size="sm" tone="stop" />
      </div>
      {over !== null && over > 1 ? (
        <p className={styles.over}>
          {over >= 10 ? Math.round(over) : over.toFixed(1)}× over the limit
        </p>
      ) : null}
    </div>
  );
}
