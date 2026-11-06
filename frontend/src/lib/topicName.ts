// A random ntfy topic name, made in the browser (Req 21.17).
//
// On a public ntfy server the topic is the only thing between an alert and
// anyone who guesses its name, so the dashboard offers one that cannot be
// guessed. It is generated here and never sent to the server: CveDeck reads
// its destination from the environment alone (Req 21.10), and a suggestion the
// server had seen would be one more place the secret lived.

const ALPHABET = "abcdefghijklmnopqrstuvwxyz0123456789";
/** Random characters after the prefix: about 124 bits. */
export const TOPIC_RANDOM_LENGTH = 24;
export const TOPIC_PREFIX = "cvd-";

type RandomBytes = (count: number) => Uint8Array;

const cryptoBytes: RandomBytes = (count) => crypto.getRandomValues(new Uint8Array(count));

/** Whether a topic meets the rule the server applies (letters and digits, 20+). */
export function isStrongTopic(topic: string): boolean {
  return topic.length >= 20 && /[A-Za-z]/.test(topic) && /[0-9]/.test(topic);
}

/**
 * `cvd-` plus 24 lowercase letters and digits, by rejection sampling so every
 * character is equally likely (252 is the largest multiple of 36 below 256).
 * Redrawn in the rare case it has no digit or no letter.
 */
export function randomTopicName(randomBytes: RandomBytes = cryptoBytes): string {
  for (;;) {
    let chars = "";
    while (chars.length < TOPIC_RANDOM_LENGTH) {
      for (const byte of randomBytes(TOPIC_RANDOM_LENGTH * 2)) {
        if (byte < 252 && chars.length < TOPIC_RANDOM_LENGTH) chars += ALPHABET[byte % 36];
      }
    }
    const topic = TOPIC_PREFIX + chars;
    if (isStrongTopic(topic)) return topic;
  }
}
