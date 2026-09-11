"use client";

import type { ApiClaimReason, ApiEvidenceArtifact } from "@/lib/intentguard-api";
import styles from "./CaseFile.module.css";

export type CaseFileData = {
  orderReference: string | null;
  reason: ApiClaimReason;
  orderValue: string;
  daysSinceDelivery: number;
  artifacts: ApiEvidenceArtifact[];
  /** The customer's own words. Untrusted -- see the note in the markup. */
  complaint: string | null;
  /** Demo fixtures only, keyed by artifact reference. Real deployments link
   *  out to the merchant's order system; the gateway stores no images. */
  previews?: Record<string, string>;
};

const REASON_LABEL: Record<ApiClaimReason, string> = {
  defect: "Arrived damaged",
  not_delivered: "Never arrived",
  late: "Arrived late",
  changed_mind: "Changed their mind",
};

const KIND_LABEL: Record<ApiEvidenceArtifact["kind"], string> = {
  photo: "Photo",
  receipt: "Receipt",
  courier_scan: "Courier scan",
};

function Receipt({ reference, orderReference, orderValue }: {
  reference: string;
  orderReference: string | null;
  orderValue: string;
}) {
  return (
    <div className={styles.receipt} aria-label="Bill receipt">
      <div className={styles.receiptHead}>RECEIPT</div>
      <dl className={styles.receiptRows}>
        <div><dt>Order</dt><dd>{orderReference ?? "—"}</dd></div>
        <div><dt>Item</dt><dd>1 × item</dd></div>
        <div><dt>Paid</dt><dd>₹{orderValue}</dd></div>
      </dl>
      <div className={styles.receiptRule} />
      <div className={styles.receiptRef}>{reference}</div>
    </div>
  );
}

export function CaseFile({ data }: { data: CaseFileData }) {
  const { artifacts, previews = {} } = data;

  return (
    <section className={styles.file}>
      <header className={styles.head}>
        <div>
          <h2 className={styles.title}>Case file</h2>
          <p className={styles.sub}>
            What the agent was looking at when it proposed a remedy.
          </p>
        </div>
        <div className={styles.ids}>
          <span className={styles.order}>{data.orderReference ?? "no order id"}</span>
          <span className={styles.reason}>{REASON_LABEL[data.reason]}</span>
        </div>
      </header>

      <dl className={styles.facts}>
        <div><dt>Order value</dt><dd>₹{data.orderValue}</dd></div>
        <div>
          <dt>Since delivery</dt>
          <dd>
            {data.daysSinceDelivery} day{data.daysSinceDelivery === 1 ? "" : "s"}
          </dd>
        </div>
        <div><dt>Evidence</dt><dd>{artifacts.length || "none"}</dd></div>
      </dl>

      {data.complaint ? (
        <figure className={styles.quoteBlock}>
          <figcaption className={styles.quoteLabel}>
            Customer&rsquo;s words &middot; unverified
          </figcaption>
          {/* Rendered as text, never as markup. This string is attacker-
              controlled: it reaches the agent as well, so it is already an
              injection surface, and it must never be styled to look like
              something the system said. */}
          <blockquote className={styles.quote}>{data.complaint}</blockquote>
        </figure>
      ) : null}

      {artifacts.length > 0 ? (
        <ul className={styles.evidence}>
          {artifacts.map((artifact) => {
            const preview = previews[artifact.reference];
            return (
              <li className={styles.item} key={`${artifact.kind}:${artifact.reference}`}>
                <div className={styles.frame}>
                  {artifact.kind === "receipt" ? (
                    <Receipt
                      reference={artifact.reference}
                      orderReference={data.orderReference}
                      orderValue={data.orderValue}
                    />
                  ) : preview ? (
                    // A bundled demo fixture at a fixed size, not user
                    // content: next/image would add an optimiser pass for a
                    // static asset the page already knows the dimensions of.
                    // eslint-disable-next-line @next/next/no-img-element
                    <img
                      alt={`${KIND_LABEL[artifact.kind]} supplied with the claim`}
                      className={styles.shot}
                      src={preview}
                    />
                  ) : (
                    <div className={styles.missing}>
                      Held in the order system
                    </div>
                  )}
                </div>
                <div className={styles.meta}>
                  <span className={styles.kind}>{KIND_LABEL[artifact.kind]}</span>
                  <code className={styles.ref}>{artifact.reference}</code>
                </div>
              </li>
            );
          })}
        </ul>
      ) : (
        <p className={styles.none}>
          No evidence cited. Policy treats an unevidenced claim more narrowly.
        </p>
      )}
    </section>
  );
}
