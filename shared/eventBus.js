// shared/eventBus.js - Voice Platform Event Bus
const EventEmitter = require('events');
const Redis = require('redis');

class VoicePlatformEventBus {
  constructor() {
    this.localEmitter = new EventEmitter();
    this.redisClient = null;
    this.isConnected = false;
    this.serviceName = process.env.SERVICE_NAME || 'gateway-service';
    this.setupRedis();
  }

  async setupRedis() {
    try {
      this.redisClient = Redis.createClient({
        url: process.env.REDIS_URL || 'redis://localhost:6379',
        socket: {
          connectTimeout: 5000,
          lazyConnect: true
        }
      });
      
      this.redisClient.on('error', (err) => {
        console.warn(`[${this.serviceName.toUpperCase()}] Redis error:`, err.message);
        this.isConnected = false;
      });

      this.redisClient.on('connect', () => {
        console.log(`[${this.serviceName.toUpperCase()}] Redis connected`);
        this.isConnected = true;
      });
      
      await this.redisClient.connect();
      
      // Subscribe to voice platform events
      await this.redisClient.pSubscribe('voice-platform:*', (message, channel) => {
        try {
          const eventName = channel.replace('voice-platform:', '');
          const eventData = JSON.parse(message);
          
          console.log(`[${this.serviceName.toUpperCase()}] Event received: ${eventName}`);
          this.localEmitter.emit(eventName, eventData);
        } catch (error) {
          console.error(`[${this.serviceName.toUpperCase()}] Event parsing error:`, error.message);
        }
      });
      
      this.isConnected = true;
      console.log(`[${this.serviceName.toUpperCase()}] Event bus connected and subscribed`);
      
    } catch (error) {
      console.warn(`[${this.serviceName.toUpperCase()}] Event bus unavailable, using local events only:`, error.message);
      this.isConnected = false;
    }
  }

  async emit(eventName, eventData) {
    const enrichedData = {
      ...eventData,
      timestamp: new Date().toISOString(),
      eventId: `evt_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
      source: this.serviceName,
      version: '2.1.0'
    };

    // Always emit locally
    this.localEmitter.emit(eventName, enrichedData);

    // Emit to Redis if connected
    if (this.redisClient && this.isConnected) {
      try {
        await this.redisClient.publish(
          `voice-platform:${eventName}`, 
          JSON.stringify(enrichedData)
        );
        console.log(`[${this.serviceName.toUpperCase()}] Event emitted: ${eventName}`);
      } catch (error) {
        console.warn(`[${this.serviceName.toUpperCase()}] Failed to emit ${eventName}:`, error.message);
      }
    }

    return enrichedData;
  }

  on(eventName, handler) {
    this.localEmitter.on(eventName, handler);
  }

  off(eventName, handler) {
    this.localEmitter.off(eventName, handler);
  }

  async close() {
    if (this.redisClient && this.isConnected) {
      await this.redisClient.quit();
    }
  }

  getStatus() {
    return {
      connected: this.isConnected,
      serviceName: this.serviceName,
      eventCount: this.localEmitter.eventNames().length
    };
  }
}

module.exports = new VoicePlatformEventBus();
