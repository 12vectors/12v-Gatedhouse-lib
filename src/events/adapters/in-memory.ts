/**
 * In-memory event bus adapter for testing and single-instance deployments.
 */

import { EventBusAdapter, EventHandler, GatehouseEvent } from '../../types';
import { createLogger } from '../../logger';

const logger = createLogger('event-bus:in-memory');

export class InMemoryEventBus implements EventBusAdapter {
  private handlers: Map<string, EventHandler[]> = new Map();
  private allHandlers: EventHandler[] = [];

  async subscribe(topics: string[], handler: EventHandler): Promise<void> {
    for (const topic of topics) {
      if (topic.endsWith('.*') || topic.endsWith('*')) {
        // Wildcard subscription: subscribe to all
        this.allHandlers.push(handler);
        logger.info({ topic }, 'Subscribed to wildcard topic');
      } else {
        const existing = this.handlers.get(topic) ?? [];
        existing.push(handler);
        this.handlers.set(topic, existing);
        logger.info({ topic }, 'Subscribed to topic');
      }
    }
  }

  async publish(topic: string, event: GatehouseEvent): Promise<void> {
    const handlers = [
      ...(this.handlers.get(topic) ?? []),
      ...this.allHandlers,
    ];

    for (const handler of handlers) {
      try {
        await handler(event);
      } catch (err) {
        logger.error({ err, topic }, 'Handler error');
      }
    }
  }

  async disconnect(): Promise<void> {
    this.handlers.clear();
    this.allHandlers = [];
  }
}
