import styles from "./Money.module.css";

/** Renders an amount so two amounts can be compared at a glance. */
export function Money({
  amount,
  currency = "INR",
  size = "md",
  tone = "default",
}: {
  amount: string | number | null | undefined;
  currency?: string;
  size?: "sm" | "md" | "lg";
  tone?: "default" | "stop" | "pass" | "faint";
}) {
  const value = Number(amount);
  if (!Number.isFinite(value)) return <span className={styles.dash}>—</span>;
  return (
    <span className={`${styles.money} ${styles[size]} ${styles[tone]} tabular`}>
      {new Intl.NumberFormat("en-IN", {
        style: "currency",
        currency,
        maximumFractionDigits: 0,
      }).format(value)}
    </span>
  );
}
