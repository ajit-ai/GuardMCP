/**
 * Token-bucket rate limiter for NVD's strict limits.
 * Without API key: 5 requests / 30s
 * With API key:    50 requests / 30s
 */
export class RateLimiter {
  private tokens: number;
  private maxTokens: number;
  private windowMs: number;
  private queue: Array<() => void> = [];
  private refillTimer: NodeJS.Timeout | null = null;

  constructor(maxTokens: number, windowMs: number) {
    this.maxTokens = maxTokens;
    this.tokens = maxTokens;
    this.windowMs = windowMs;
  }

  async acquire(): Promise<void> {
    if (this.tokens > 0) {
      this.tokens--;
      this.scheduleRefill();
      return;
    }
    // Wait for token
    await new Promise<void>((resolve) => this.queue.push(resolve));
  }

  private scheduleRefill(): void {
    if (this.refillTimer) return;
    this.refillTimer = setTimeout(() => {
      this.tokens = this.maxTokens;
      this.refillTimer = null;
      // Drain queue up to maxTokens
      while (this.queue.length > 0 && this.tokens > 0) {
        this.tokens--;
        const next = this.queue.shift();
        next?.();
      }
      if (this.queue.length > 0) this.scheduleRefill();
    }, this.windowMs);
    // Don't block exit
    (this.refillTimer as unknown as { unref?: () => void }).unref?.();
  }
}
