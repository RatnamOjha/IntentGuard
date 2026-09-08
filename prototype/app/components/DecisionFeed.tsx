import styles from "./DecisionFeed.module.css";

export type FeedRow = {
  id: string;
  time: string;
  agent: string;
  action: string;
  amount: string;
  decision: "Allowed" | "Blocked" | "Review";
  reason: string;
};

export function DecisionFeed({ rows }: { rows: FeedRow[] }) {
  if (rows.length === 0) {
    return <p className={styles.empty}>No decisions yet. Run a request above.</p>;
  }
  return (
    <ol className={styles.feed}>
      {rows.map((row) => (
        <li className={styles.row} key={row.id}>
          <span
            className={
              row.decision === "Allowed"
                ? `${styles.pip} ${styles.pass}`
                : row.decision === "Review"
                  ? `${styles.pip} ${styles.hold}`
                  : `${styles.pip} ${styles.stop}`
            }
            aria-hidden="true"
          />
          <time className={styles.time}>{row.time}</time>
          <span className={styles.who}>{row.agent}</span>
          <span className={styles.what}>{row.action}</span>
          <span className={`${styles.amount} tabular`}>{row.amount}</span>
          <span className={styles.reason}>{row.reason}</span>
        </li>
      ))}
    </ol>
  );
}
