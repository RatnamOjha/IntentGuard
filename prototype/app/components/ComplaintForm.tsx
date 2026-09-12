"use client";

import { useRef, useState } from "react";
import {
  type ApiClaimReason,
  type ApiEvidenceKind,
  uploadEvidence,
} from "@/lib/intentguard-api";
import type { CaseEvidence, CaseRecord } from "../lib/cases";
import { REASON_LABEL } from "../lib/cases";
import styles from "./ComplaintForm.module.css";

/** Mirrors the gateway's own limit so an oversized file is refused before it
 *  is read and encoded. The server remains the authority. */
const MAX_BYTES = 5 * 1024 * 1024;
const ACCEPT = "image/jpeg,image/png,image/webp";

type Attached = CaseEvidence & { localUrl: string; name: string };

export function ComplaintForm({
  onFiled,
  busy,
}: {
  onFiled: (record: CaseRecord) => void;
  busy: boolean;
}) {
  const [reason, setReason] = useState<ApiClaimReason>("defect");
  const [orderReference, setOrderReference] = useState("ORD-88410");
  const [orderValue, setOrderValue] = useState("2400");
  const [days, setDays] = useState("2");
  const [complaint, setComplaint] = useState("");
  const [attached, setAttached] = useState<Attached[]>([]);
  const [uploading, setUploading] = useState(false);
  const [error, setError] = useState("");
  const fileInput = useRef<HTMLInputElement>(null);

  async function attach(files: FileList | null) {
    if (!files || files.length === 0) return;
    setError("");
    setUploading(true);
    try {
      for (const file of Array.from(files)) {
        if (file.size > MAX_BYTES) {
          setError(`${file.name} is larger than 5 MB.`);
          continue;
        }
        const kind: ApiEvidenceKind = /receipt|bill|invoice/i.test(file.name)
          ? "receipt"
          : "photo";
        const stored = await uploadEvidence(file, kind);
        setAttached((current) => [
          ...current,
          {
            kind: stored.kind,
            reference: stored.reference,
            localUrl: URL.createObjectURL(file),
            name: file.name,
          },
        ]);
      }
    } catch (caught) {
      setError(
        caught instanceof Error
          ? caught.message
          : "That file could not be attached.",
      );
    } finally {
      setUploading(false);
      if (fileInput.current) fileInput.current.value = "";
    }
  }

  function remove(reference: string) {
    setAttached((current) => {
      const going = current.find((item) => item.reference === reference);
      if (going) URL.revokeObjectURL(going.localUrl);
      return current.filter((item) => item.reference !== reference);
    });
  }

  function submit() {
    if (!complaint.trim()) {
      setError("Say what went wrong.");
      return;
    }
    onFiled({
      id: `case-${Date.now()}`,
      orderReference: orderReference.trim() || "ORD-UNKNOWN",
      customer: "You",
      reason,
      orderValue: orderValue.trim() || "0",
      daysSinceDelivery: Number(days) || 0,
      complaint: complaint.trim(),
      evidence: attached.map(({ kind, reference, localUrl }) => ({
        kind,
        reference,
        previewUrl: localUrl,
      })),
      filedAt: new Date().toLocaleTimeString([], {
        hour: "2-digit",
        minute: "2-digit",
      }),
      agentId: "agt_refund_01",
      intentId: "intent_refund_routine",
      proposedAction: "refund_order",
      proposedAmount: orderValue.trim() || "0",
      riskScore: 12,
    });
    setComplaint("");
    setAttached([]);
  }

  return (
    <section className={styles.form}>
      <header>
        <h2 className={styles.title}>File a complaint</h2>
        <p className={styles.sub}>
          Describe what went wrong and attach anything that shows it. You do not
          ask for an amount &mdash; the agent decides what to propose, and policy
          decides what it may honour.
        </p>
      </header>

      <div className={styles.row}>
        <label className={styles.field}>
          <span>What happened</span>
          <select
            onChange={(event) => setReason(event.target.value as ApiClaimReason)}
            value={reason}
          >
            {(Object.keys(REASON_LABEL) as ApiClaimReason[]).map((key) => (
              <option key={key} value={key}>{REASON_LABEL[key]}</option>
            ))}
          </select>
        </label>
        <label className={styles.field}>
          <span>Order</span>
          <input
            onChange={(event) => setOrderReference(event.target.value)}
            value={orderReference}
          />
        </label>
      </div>

      <div className={styles.row}>
        <label className={styles.field}>
          <span>Order value (₹)</span>
          <input
            inputMode="numeric"
            onChange={(event) => setOrderValue(event.target.value)}
            value={orderValue}
          />
        </label>
        <label className={styles.field}>
          <span>Days since delivery</span>
          <input
            inputMode="numeric"
            onChange={(event) => setDays(event.target.value)}
            value={days}
          />
        </label>
      </div>

      <label className={styles.field}>
        <span>In your words</span>
        <textarea
          onChange={(event) => setComplaint(event.target.value)}
          placeholder="The dinner set arrived with three plates broken…"
          rows={4}
          value={complaint}
        />
      </label>

      <div className={styles.attach}>
        <input
          accept={ACCEPT}
          className={styles.file}
          id="evidence-input"
          multiple
          onChange={(event) => void attach(event.target.files)}
          ref={fileInput}
          type="file"
        />
        <label className={styles.attachButton} htmlFor="evidence-input">
          {uploading ? "Uploading…" : "Attach photo or receipt"}
        </label>
        <span className={styles.attachHint}>JPEG, PNG or WebP · up to 5 MB</span>
      </div>

      {attached.length > 0 ? (
        <ul className={styles.attached}>
          {attached.map((item) => (
            <li className={styles.thumb} key={item.reference}>
              {/* eslint-disable-next-line @next/next/no-img-element */}
              <img alt={item.name} src={item.localUrl} />
              <button onClick={() => remove(item.reference)} type="button">
                Remove
              </button>
            </li>
          ))}
        </ul>
      ) : null}

      {error ? <p className={styles.error}>{error}</p> : null}

      <button
        className={styles.submit}
        disabled={busy || uploading || !complaint.trim()}
        onClick={submit}
        type="button"
      >
        Send it to support
        <span aria-hidden="true"> →</span>
      </button>
    </section>
  );
}
