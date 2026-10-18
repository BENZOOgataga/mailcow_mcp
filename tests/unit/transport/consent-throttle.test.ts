/**
 * Consent-route backoff schedule.
 *
 * The schedule is tested here rather than against a live server because the
 * only way to observe it over HTTP is to wait for it, and nobody runs a test
 * that waits out a 30 second step twice.
 *
 * It exists because of two specific mistakes:
 *
 *   - The backoff was first keyed on a hash of the consent blob, so that one
 *     caller's failures could not slow another's. An attacker resets that for
 *     free: `/authorize` needs no authentication and dynamic registration is
 *     open, so they fetch a fresh consent page before each guess, every guess
 *     is the first failure for its own key, and the delay never leaves its
 *     first step. The count has to be global to mean anything.
 *   - The replaced SDK limiter answered 429, which let an attacker lock the
 *     operator out of their own consent screen. Throttling by delay rather
 *     than refusal is what removes that, so the schedule must never reach a
 *     point where it stops answering.
 */

import { consentDelayFor } from '../../../src/transport/http';

describe('consentDelayFor', () => {
  it('starts at one second', () => {
    expect(consentDelayFor(1)).toBe(1000);
  });

  it('doubles with each failure', () => {
    expect(consentDelayFor(2)).toBe(2000);
    expect(consentDelayFor(3)).toBe(4000);
    expect(consentDelayFor(4)).toBe(8000);
    expect(consentDelayFor(5)).toBe(16000);
  });

  it('caps so a held socket is bounded', () => {
    expect(consentDelayFor(6)).toBe(30000);
    expect(consentDelayFor(50)).toBe(30000);
    expect(consentDelayFor(10_000)).toBe(30000);
  });

  it('never decreases as failures accumulate', () => {
    let previous = 0;
    for (let n = 1; n <= 40; n++) {
      const delay = consentDelayFor(n);
      expect(delay).toBeGreaterThanOrEqual(previous);
      previous = delay;
    }
  });

  it('always returns a finite delay rather than a refusal', () => {
    // The schedule has no "give up" value. A wrong password is always
    // eventually answered, which is what stops an attacker from using it to
    // lock the operator out.
    for (const n of [0, 1, 7, 1000]) {
      const delay = consentDelayFor(n);
      expect(Number.isFinite(delay)).toBe(true);
      expect(delay).toBeGreaterThan(0);
      expect(delay).toBeLessThanOrEqual(30000);
    }
  });

  it('treats a zero or negative count as the first failure', () => {
    expect(consentDelayFor(0)).toBe(1000);
    expect(consentDelayFor(-5)).toBe(1000);
  });
});
