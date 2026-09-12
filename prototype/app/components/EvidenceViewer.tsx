"use client";

import { useEffect, useState } from "react";
import { fetchEvidenceObjectUrl } from "@/lib/intentguard-api";
import type { CaseEvidence } from "../lib/cases";
import styles from "./EvidenceViewer.module.css";

const KIND_LABEL: Record<CaseEvidence["kind"], string> = {
  photo: "Photo",
  receipt: "Receipt",
  courier_scan: "Courier scan",
};

/** Resolve one artifact to something an <img> can show.
 *
 *  Bundled fixtures already have a URL. Uploaded evidence is fetched with the
 *  access token and handed over as a blob, because an <img src> cannot carry
 *  an Authorization header and the endpoint requires one. */
function useEvidenceUrl(artifact: CaseEvidence): string | null {
  // A bundled fixture already has its URL, so it is derived rather than
  // stored: setting state for it synchronously inside the effect would
  // trigger a cascading render. Only the fetched blob needs state.
  const needsFetch =
    !artifact.previewUrl && artifact.reference.startsWith("ev_");
  const [fetched, setFetched] = useState<string | null>(null);

  useEffect(() => {
    if (!needsFetch) return;
    let cancelled = false;
    let objectUrl: string | null = null;
    void fetchEvidenceObjectUrl(artifact.reference)
      .then((next) => {
        if (cancelled) {
          URL.revokeObjectURL(next);
          return;
        }
        objectUrl = next;
        setFetched(next);
      })
      .catch(() => undefined);
    return () => {
      cancelled = true;
      // Without this the blob is retained for the life of the document.
      if (objectUrl) URL.revokeObjectURL(objectUrl);
    };
  }, [needsFetch, artifact.reference]);

  return artifact.previewUrl ?? fetched;
}

function Receipt({ orderReference, orderValue, reference }: {
  orderReference: string;
  orderValue: string;
  reference: string;
}) {
  return (
    <div className={styles.receipt}>
      <div className={styles.receiptHead}>RECEIPT</div>
      <dl className={styles.receiptRows}>
        <div><dt>Order</dt><dd>{orderReference}</dd></div>
        <div><dt>Paid</dt><dd>₹{orderValue}</dd></div>
      </dl>
      <div className={styles.receiptRule} />
      <div className={styles.receiptRef}>{reference}</div>
    </div>
  );
}

function Tile({ artifact, orderReference, orderValue, onOpen }: {
  artifact: CaseEvidence;
  orderReference: string;
  orderValue: string;
  onOpen: (url: string) => void;
}) {
  const url = useEvidenceUrl(artifact);
  const openable = url !== null && artifact.kind !== "receipt";

  return (
    <li className={styles.item}>
      <button
        className={styles.frame}
        disabled={!openable}
        onClick={() => url && onOpen(url)}
        type="button"
        aria-label={
          openable ? `Open ${KIND_LABEL[artifact.kind]} full size` : undefined
        }
      >
        {artifact.kind === "receipt" ? (
          <Receipt
            orderReference={orderReference}
            orderValue={orderValue}
            reference={artifact.reference}
          />
        ) : url ? (
          // eslint-disable-next-line @next/next/no-img-element
          <img alt={`${KIND_LABEL[artifact.kind]} filed with the claim`} className={styles.shot} src={url} />
        ) : (
          <span className={styles.held}>Held in the order system</span>
        )}
        {openable ? <span className={styles.zoom}>⤢</span> : null}
      </button>
      <div className={styles.meta}>
        <span className={styles.kind}>{KIND_LABEL[artifact.kind]}</span>
        <code className={styles.ref}>{artifact.reference}</code>
      </div>
    </li>
  );
}

export function EvidenceViewer({
  evidence,
  orderReference,
  orderValue,
}: {
  evidence: CaseEvidence[];
  orderReference: string;
  orderValue: string;
}) {
  const [lightbox, setLightbox] = useState<string | null>(null);

  useEffect(() => {
    if (!lightbox) return;
    const onKey = (event: KeyboardEvent) => {
      if (event.key === "Escape") setLightbox(null);
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [lightbox]);

  if (evidence.length === 0) {
    return (
      <p className={styles.none}>
        No evidence filed. Policy settles an unevidenced claim more narrowly.
      </p>
    );
  }

  return (
    <>
      <ul className={styles.grid}>
        {evidence.map((artifact) => (
          <Tile
            artifact={artifact}
            key={`${artifact.kind}:${artifact.reference}`}
            onOpen={setLightbox}
            orderReference={orderReference}
            orderValue={orderValue}
          />
        ))}
      </ul>
      {lightbox ? (
        <div
          className={styles.lightbox}
          onClick={() => setLightbox(null)}
          role="presentation"
        >
          {/* eslint-disable-next-line @next/next/no-img-element */}
          <img alt="Evidence, full size" className={styles.full} src={lightbox} />
          <button className={styles.close} type="button">Close</button>
        </div>
      ) : null}
    </>
  );
}
