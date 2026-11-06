// Feature: notifications -- the suggested ntfy topic always passes the rule the
// server applies to a public topic (Req 21.17).

import { describe, expect, it } from "vitest";
import fc from "fast-check";
import { isStrongTopic, randomTopicName, TOPIC_PREFIX, TOPIC_RANDOM_LENGTH } from "./topicName";

describe("randomTopicName", () => {
  it("is cvd- and 24 lowercase letters and digits", () => {
    const topic = randomTopicName();
    expect(topic).toMatch(/^cvd-[a-z0-9]{24}$/);
    expect(isStrongTopic(topic)).toBe(true);
  });

  it("differs every time", () => {
    const seen = new Set(Array.from({ length: 50 }, () => randomTopicName()));
    expect(seen.size).toBe(50);
  });

  it("is always strong, whatever bytes the source returns", () => {
    fc.assert(
      fc.property(fc.array(fc.integer({ min: 0, max: 255 }), { minLength: 1, maxLength: 64 }), (pool) => {
        // Cycle a fixed pool, offset each call, so even a degenerate source
        // (all digits, all letters, all rejected bytes) is exercised.
        let offset = 0;
        const source = (count: number) => {
          const out = new Uint8Array(count);
          for (let i = 0; i < count; i++) out[i] = pool[(offset + i) % pool.length];
          offset += count + 1;
          // Guarantee progress: mix in the call number so a pool of rejected
          // bytes cannot loop for ever.
          if (offset > 10_000) for (let i = 0; i < count; i++) out[i] = (i * 7 + offset) % 252;
          return out;
        };
        const topic = randomTopicName(source);
        expect(topic.startsWith(TOPIC_PREFIX)).toBe(true);
        expect(topic.length).toBe(TOPIC_PREFIX.length + TOPIC_RANDOM_LENGTH);
        expect(isStrongTopic(topic)).toBe(true);
      }),
      { numRuns: 100 },
    );
  });

  it("never uses a byte of 252 or more, so no character is favoured", () => {
    const calls: number[] = [];
    const topic = randomTopicName((count) => {
      calls.push(count);
      // 252..255 would map to "a".."d" a second time; they must be skipped.
      return calls.length === 1 ? new Uint8Array(count).fill(252) : Uint8Array.from({ length: count }, (_, i) => (i % 2 ? 26 : 0));
    });
    expect(topic).toBe("cvd-a0a0a0a0a0a0a0a0a0a0a0a0");
    expect(calls.length).toBeGreaterThan(1);
  });
});

describe("isStrongTopic", () => {
  it.each([
    ["alerts", false],
    ["cvedeck-fleet-alerts-home", false],
    ["12345678901234567890", false],
    ["cvd-7k2m9q4x8r1t6w3p", true],
  ])("%s -> %s", (topic, strong) => {
    expect(isStrongTopic(topic)).toBe(strong);
  });
});
