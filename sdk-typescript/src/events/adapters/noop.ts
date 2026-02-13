/**
 * No-op event bus adapter.
 *
 * Used when the consuming service manages its own event ingestion
 * and feeds events into Gatedhouse programmatically.
 */

import { EventBusAdapter, EventHandler } from '../../types';

export class NoopEventBus implements EventBusAdapter {
  async subscribe(_topics: string[], _handler: EventHandler): Promise<void> {
    // No-op: events are fed manually via gatedhouse.handleEvent()
  }

  async publish(_topic: string): Promise<void> {
    // No-op
  }

  async disconnect(): Promise<void> {
    // No-op
  }
}
