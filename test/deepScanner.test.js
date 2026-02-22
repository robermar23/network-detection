import { describe, it, expect } from 'vitest';
import { cancelDeepScan } from '../src/main/deepScanner.js';

describe('Deep Scanner Module', () => {
  it('should safely accept cancellation instructions for an explicit IP address', () => {
    expect(() => cancelDeepScan('10.0.0.1')).not.toThrow();
  });
  
  it('should silently handle cancellation instructions for IP addresses not currently in the active scan pool', () => {
    expect(() => cancelDeepScan('255.255.255.255')).not.toThrow();
  });
});
