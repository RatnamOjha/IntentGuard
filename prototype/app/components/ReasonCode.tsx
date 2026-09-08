import styles from "./ReasonCode.module.css";

/**
 * A policy finding's machine-readable code. Rendered identically everywhere so
 * an operator learns to recognise the vocabulary.
 */
export function ReasonCode({
  code,
  tone = "stop",
}: {
  code: string;
  tone?: "stop" | "hold" | "soft";
}) {
  return <code className={`${styles.code} ${styles[tone]}`}>{code}</code>;
}
