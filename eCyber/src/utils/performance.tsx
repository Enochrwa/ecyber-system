// Frontend Performance Optimization Utilities
// Core performance monitoring without JSX components

import { useEffect, useRef, useState, useCallback } from 'react';

// Performance monitoring types
interface PerformanceMetrics {
  timestamp: number;
  loadTime: number;
  renderTime: number;
  memoryUsage?: number;
  networkRequests: number;
  errorCount: number;
  userInteractions: number;
}

interface ComponentMetrics {
  componentName: string;
  renderCount: number;
  averageRenderTime: number;
  lastRenderTime: number;
  propsChanges: number;
}

// Performance monitoring class
class FrontendPerformanceMonitor {
  private metrics: PerformanceMetrics[] = [];
  private componentMetrics: Map<string, ComponentMetrics> = new Map();
  private observer: PerformanceObserver | null = null;
  private isMonitoring = false;

  start() {
    if (this.isMonitoring) return;
    
    this.isMonitoring = true;
    
    // Monitor performance entries
    if ('PerformanceObserver' in window) {
      this.observer = new PerformanceObserver((list) => {
        const entries = list.getEntries();
        this.processPerformanceEntries(entries);
      });
      
      this.observer.observe({ 
        entryTypes: ['navigation', 'resource', 'measure', 'paint'] 
      });
    }
    
    // Monitor memory usage if available
    this.startMemoryMonitoring();
    
    // Monitor user interactions
    this.startInteractionMonitoring();
    
    console.log('Frontend performance monitoring started');
  }

  stop() {
    if (!this.isMonitoring) return;
    
    this.isMonitoring = false;
    
    if (this.observer) {
      this.observer.disconnect();
      this.observer = null;
    }
    
    console.log('Frontend performance monitoring stopped');
  }

  private processPerformanceEntries(entries: PerformanceEntry[]) {
    entries.forEach(entry => {
      if (entry.entryType === 'navigation') {
        const navEntry = entry as PerformanceNavigationTiming;
        this.recordMetric({
          timestamp: Date.now(),
          loadTime: navEntry.loadEventEnd - navEntry.navigationStart,
          renderTime: navEntry.domContentLoadedEventEnd - navEntry.domContentLoadedEventStart,
          networkRequests: 0,
          errorCount: 0,
          userInteractions: 0
        });
      }
    });
  }

  private startMemoryMonitoring() {
    if ('memory' in performance) {
      setInterval(() => {
        const memory = (performance as any).memory;
        if (memory) {
          const latest = this.metrics[this.metrics.length - 1];
          if (latest) {
            latest.memoryUsage = memory.usedJSHeapSize;
          }
        }
      }, 5000);
    }
  }

  private startInteractionMonitoring() {
    let interactionCount = 0;
    
    const trackInteraction = () => {
      interactionCount++;
      const latest = this.metrics[this.metrics.length - 1];
      if (latest) {
        latest.userInteractions = interactionCount;
      }
    };
    
    ['click', 'keydown', 'scroll', 'touchstart'].forEach(event => {
      document.addEventListener(event, trackInteraction, { passive: true });
    });
  }

  recordMetric(metric: PerformanceMetrics) {
    this.metrics.push(metric);
    
    if (this.metrics.length > 100) {
      this.metrics.shift();
    }
  }

  recordComponentRender(componentName: string, renderTime: number) {
    const existing = this.componentMetrics.get(componentName);
    
    if (existing) {
      existing.renderCount++;
      existing.averageRenderTime = 
        (existing.averageRenderTime * (existing.renderCount - 1) + renderTime) / existing.renderCount;
      existing.lastRenderTime = renderTime;
    } else {
      this.componentMetrics.set(componentName, {
        componentName,
        renderCount: 1,
        averageRenderTime: renderTime,
        lastRenderTime: renderTime,
        propsChanges: 0
      });
    }
  }

  getMetrics(): PerformanceMetrics[] {
    return [...this.metrics];
  }

  getComponentMetrics(): ComponentMetrics[] {
    return Array.from(this.componentMetrics.values());
  }

  getPerformanceReport() {
    const metrics = this.getMetrics();
    const componentMetrics = this.getComponentMetrics();
    
    if (metrics.length === 0) {
      return { error: 'No performance data available' };
    }
    
    const avgLoadTime = metrics.reduce((sum, m) => sum + m.loadTime, 0) / metrics.length;
    const avgRenderTime = metrics.reduce((sum, m) => sum + m.renderTime, 0) / metrics.length;
    const totalInteractions = metrics[metrics.length - 1]?.userInteractions || 0;
    
    const slowComponents = componentMetrics
      .filter(c => c.averageRenderTime > 16)
      .sort((a, b) => b.averageRenderTime - a.averageRenderTime);
    
    return {
      summary: {
        averageLoadTime: avgLoadTime,
        averageRenderTime: avgRenderTime,
        totalUserInteractions: totalInteractions,
        slowComponentsCount: slowComponents.length
      },
      slowComponents,
      recommendations: this.generateRecommendations(metrics, componentMetrics)
    };
  }

  private generateRecommendations(
    metrics: PerformanceMetrics[], 
    componentMetrics: ComponentMetrics[]
  ): string[] {
    const recommendations: string[] = [];
    
    const avgLoadTime = metrics.reduce((sum, m) => sum + m.loadTime, 0) / metrics.length;
    if (avgLoadTime > 3000) {
      recommendations.push('Page load time is high - consider code splitting and lazy loading');
    }
    
    const slowComponents = componentMetrics.filter(c => c.averageRenderTime > 16);
    if (slowComponents.length > 0) {
      recommendations.push(`${slowComponents.length} components have slow render times - consider optimization`);
    }
    
    const frequentlyRenderingComponents = componentMetrics.filter(c => c.renderCount > 100);
    if (frequentlyRenderingComponents.length > 0) {
      recommendations.push('Some components render frequently - consider memoization');
    }
    
    return recommendations;
  }
}

// Global performance monitor instance
export const performanceMonitor = new FrontendPerformanceMonitor();

// React hooks for performance optimization

// Hook to measure component render time
export const useRenderTime = (componentName: string) => {
  const renderStartTime = useRef<number>(0);
  
  useEffect(() => {
    renderStartTime.current = performance.now();
  });
  
  useEffect(() => {
    const renderTime = performance.now() - renderStartTime.current;
    performanceMonitor.recordComponentRender(componentName, renderTime);
  });
};

// Hook for debounced values to reduce unnecessary re-renders
export const useDebounce = <T>(value: T, delay: number): T => {
  const [debouncedValue, setDebouncedValue] = useState<T>(value);

  useEffect(() => {
    const handler = setTimeout(() => {
      setDebouncedValue(value);
    }, delay);

    return () => {
      clearTimeout(handler);
    };
  }, [value, delay]);

  return debouncedValue;
};

// Hook for intersection observer (lazy loading)
export const useIntersectionObserver = (
  elementRef: React.RefObject<Element>,
  options: IntersectionObserverInit = {}
) => {
  const [isIntersecting, setIsIntersecting] = useState(false);
  const [hasIntersected, setHasIntersected] = useState(false);

  useEffect(() => {
    const element = elementRef.current;
    if (!element) return;

    const observer = new IntersectionObserver(([entry]) => {
      setIsIntersecting(entry.isIntersecting);
      if (entry.isIntersecting && !hasIntersected) {
        setHasIntersected(true);
      }
    }, options);

    observer.observe(element);

    return () => {
      observer.unobserve(element);
    };
  }, [elementRef, options, hasIntersected]);

  return { isIntersecting, hasIntersected };
};

// Hook for optimized API calls with caching
export const useOptimizedFetch = <T>(
  url: string,
  options: RequestInit = {},
  dependencies: any[] = []
) => {
  const [data, setData] = useState<T | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const cache = useRef<Map<string, { data: T; timestamp: number }>>(new Map());
  
  const fetchData = useCallback(async () => {
    const cacheKey = url + JSON.stringify(options);
    const cached = cache.current.get(cacheKey);
    
    if (cached && Date.now() - cached.timestamp < 300000) {
      setData(cached.data);
      return;
    }
    
    setLoading(true);
    setError(null);
    
    try {
      const response = await fetch(url, options);
      if (!response.ok) {
        throw new Error(`HTTP error! status: ${response.status}`);
      }
      
      const result = await response.json();
      setData(result);
      
      cache.current.set(cacheKey, { data: result, timestamp: Date.now() });
      
    } catch (err) {
      setError(err instanceof Error ? err.message : 'An error occurred');
    } finally {
      setLoading(false);
    }
  }, [url, JSON.stringify(options)]);
  
  useEffect(() => {
    fetchData();
  }, [fetchData, ...dependencies]);
  
  return { data, loading, error, refetch: fetchData };
};

// Simple performance monitoring component
interface PerformanceMonitorProps {
  enabled?: boolean;
  reportInterval?: number;
}

export const PerformanceMonitorComponent: React.FC<PerformanceMonitorProps> = ({
  enabled = true,
  reportInterval = 30000
}) => {
  useEffect(() => {
    if (!enabled) return;
    
    performanceMonitor.start();
    
    const interval = setInterval(() => {
      const report = performanceMonitor.getPerformanceReport();
      console.log('Performance Report:', report);
    }, reportInterval);
    
    return () => {
      clearInterval(interval);
      performanceMonitor.stop();
    };
  }, [enabled, reportInterval]);
  
  return null;
};

// Export performance monitoring functions
export const startPerformanceMonitoring = () => {
  performanceMonitor.start();
};

export const stopPerformanceMonitoring = () => {
  performanceMonitor.stop();
};

export const getPerformanceReport = () => {
  return performanceMonitor.getPerformanceReport();
};

// Performance optimization utilities
export const optimizationUtils = {
  preloadResource: (href: string, as: string) => {
    const link = document.createElement('link');
    link.rel = 'preload';
    link.href = href;
    link.as = as;
    document.head.appendChild(link);
  },

  prefetchResource: (href: string) => {
    const link = document.createElement('link');
    link.rel = 'prefetch';
    link.href = href;
    document.head.appendChild(link);
  },

  measurePerformance: (name: string, fn: () => void) => {
    const start = performance.now();
    fn();
    const end = performance.now();
    console.log(`${name} took ${end - start} milliseconds`);
  }
};

