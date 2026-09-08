import type { ReactNode } from "react";
import styles from "./Panel.module.css";

export function Panel({
  title,
  hint,
  action,
  children,
  id,
}: {
  title: string;
  hint?: string;
  action?: ReactNode;
  children: ReactNode;
  id?: string;
}) {
  return (
    <section className={styles.panel} id={id}>
      <header className={styles.head}>
        <div>
          <h2 className={styles.title}>{title}</h2>
          {hint ? <p className={styles.hint}>{hint}</p> : null}
        </div>
        {action}
      </header>
      {children}
    </section>
  );
}
