// The frame shared by the setup and sign-in pages: the wordmark, a title, and
// the form. The wordmark is the same markup as the app header's, so the first
// screen someone sees is recognisably the product rather than a generic login.

import type { ReactNode } from "react";
import { Icon } from "./Icon";

export interface AuthCardProps {
  title: string;
  intro?: ReactNode;
  children: ReactNode;
}

export function AuthCard({ title, intro, children }: AuthCardProps) {
  return (
    <main className="auth-shell">
      <section className="auth-card card" aria-labelledby="auth-title">
        <p className="brand auth-brand" aria-label="CveDeck">
          <span className="brand-shield" aria-hidden="true">
            <Icon name="shield" />
          </span>
          <span className="brand-word" aria-hidden="true">
            cve<span className="brand-stamp">DECK</span>
          </span>
        </p>
        <h2 id="auth-title" className="auth-title">
          {title}
        </h2>
        {intro && <div className="auth-intro">{intro}</div>}
        {children}
      </section>
    </main>
  );
}

/** An error returned by a sign-in form, announced when it appears. */
export function AuthError({ message }: { message: string | null }) {
  if (!message) return null;
  return (
    <p role="alert" className="error-banner auth-error">
      {message}
    </p>
  );
}
