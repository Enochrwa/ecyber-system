# Database Performance Optimization Module
# Provides comprehensive database optimization, connection pooling, and query optimization

import asyncio
import logging
import time
from typing import Dict, List, Optional, Any, Callable
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from collections import defaultdict, deque
import asyncpg
import redis.asyncio as redis
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.pool import QueuePool
from sqlalchemy import text, event
from sqlalchemy.engine import Engine
import weakref

logger = logging.getLogger(__name__)

@dataclass
class QueryMetrics:
    """Query performance metrics"""
    query_hash: str
    query_text: str
    execution_time: float
    timestamp: datetime
    rows_affected: int
    database: str
    success: bool
    error_message: Optional[str] = None

@dataclass
class ConnectionPoolStats:
    """Connection pool statistics"""
    pool_name: str
    size: int
    checked_in: int
    checked_out: int
    overflow: int
    invalid: int
    total_connections_created: int
    total_queries_executed: int
    average_query_time: float
    peak_connections: int

class QueryOptimizer:
    """Advanced query optimization and monitoring"""
    
    def __init__(self, config: Dict[str, Any] = None):
        self.config = config or {}
        self.query_metrics: deque = deque(maxlen=10000)
        self.slow_query_threshold = self.config.get('slow_query_threshold', 1.0)  # seconds
        self.query_cache: Dict[str, Any] = {}
        self.query_plans: Dict[str, Dict] = {}
        
    def record_query(self, query_metrics: QueryMetrics):
        """Record query execution metrics"""
        self.query_metrics.append(query_metrics)
        
        # Log slow queries
        if query_metrics.execution_time > self.slow_query_threshold:
            logger.warning(
                f"Slow query detected: {query_metrics.execution_time:.3f}s - "
                f"{query_metrics.query_text[:100]}..."
            )
    
    def get_slow_queries(self, hours: int = 1) -> List[QueryMetrics]:
        """Get slow queries from the specified time period"""
        cutoff_time = datetime.now() - timedelta(hours=hours)
        return [
            q for q in self.query_metrics 
            if q.timestamp >= cutoff_time and q.execution_time > self.slow_query_threshold
        ]
    
    def get_query_statistics(self) -> Dict[str, Any]:
        """Get comprehensive query statistics"""
        if not self.query_metrics:
            return {}
        
        total_queries = len(self.query_metrics)
        successful_queries = sum(1 for q in self.query_metrics if q.success)
        failed_queries = total_queries - successful_queries
        
        execution_times = [q.execution_time for q in self.query_metrics if q.success]
        avg_execution_time = sum(execution_times) / len(execution_times) if execution_times else 0
        
        slow_queries = [q for q in self.query_metrics if q.execution_time > self.slow_query_threshold]
        
        # Query frequency analysis
        query_frequency = defaultdict(int)
        for q in self.query_metrics:
            query_frequency[q.query_hash] += 1
        
        most_frequent = sorted(query_frequency.items(), key=lambda x: x[1], reverse=True)[:10]
        
        return {
            'total_queries': total_queries,
            'successful_queries': successful_queries,
            'failed_queries': failed_queries,
            'success_rate': successful_queries / total_queries if total_queries > 0 else 0,
            'average_execution_time': avg_execution_time,
            'slow_queries_count': len(slow_queries),
            'most_frequent_queries': most_frequent,
            'queries_per_second': self._calculate_qps()
        }
    
    def _calculate_qps(self) -> float:
        """Calculate queries per second"""
        if len(self.query_metrics) < 2:
            return 0.0
        
        recent_queries = [q for q in self.query_metrics if 
                         (datetime.now() - q.timestamp).seconds < 60]
        
        return len(recent_queries) / 60.0 if recent_queries else 0.0
    
    def suggest_optimizations(self) -> List[str]:
        """Suggest query optimizations based on metrics"""
        suggestions = []
        
        slow_queries = self.get_slow_queries(hours=24)
        if slow_queries:
            suggestions.append(f"Found {len(slow_queries)} slow queries in the last 24 hours - consider adding indexes or optimizing queries")
        
        stats = self.get_query_statistics()
        if stats.get('success_rate', 1.0) < 0.95:
            suggestions.append("Query success rate is below 95% - investigate failing queries")
        
        if stats.get('average_execution_time', 0) > 0.5:
            suggestions.append("Average query execution time is high - consider query optimization")
        
        return suggestions

class AsyncConnectionPool:
    """Advanced async connection pool with monitoring and optimization"""
    
    def __init__(self, database_url: str, config: Dict[str, Any] = None):
        self.database_url = database_url
        self.config = config or {}
        
        # Pool configuration
        self.min_size = self.config.get('min_size', 5)
        self.max_size = self.config.get('max_size', 20)
        self.max_queries = self.config.get('max_queries', 50000)
        self.max_inactive_connection_lifetime = self.config.get('max_inactive_connection_lifetime', 300)
        
        # Pool instance
        self.pool: Optional[asyncpg.Pool] = None
        
        # Statistics
        self.stats = ConnectionPoolStats(
            pool_name=self.config.get('name', 'default'),
            size=0,
            checked_in=0,
            checked_out=0,
            overflow=0,
            invalid=0,
            total_connections_created=0,
            total_queries_executed=0,
            average_query_time=0.0,
            peak_connections=0
        )
        
        # Query optimizer
        self.query_optimizer = QueryOptimizer(self.config.get('query_optimizer', {}))
        
    async def initialize(self):
        """Initialize the connection pool"""
        try:
            self.pool = await asyncpg.create_pool(
                self.database_url,
                min_size=self.min_size,
                max_size=self.max_size,
                max_queries=self.max_queries,
                max_inactive_connection_lifetime=self.max_inactive_connection_lifetime,
                command_timeout=self.config.get('command_timeout', 60)
            )
            
            self.stats.size = self.pool.get_size()
            self.stats.total_connections_created = self.stats.size
            
            logger.info(f"Database connection pool initialized: {self.stats.pool_name}")
            
        except Exception as e:
            logger.error(f"Failed to initialize connection pool: {e}")
            raise
    
    async def close(self):
        """Close the connection pool"""
        if self.pool:
            await self.pool.close()
            logger.info(f"Database connection pool closed: {self.stats.pool_name}")
    
    async def execute_query(self, query: str, *args, **kwargs) -> Any:
        """Execute a query with performance monitoring"""
        if not self.pool:
            raise RuntimeError("Connection pool not initialized")
        
        start_time = time.time()
        query_hash = str(hash(query))
        success = True
        error_message = None
        rows_affected = 0
        
        try:
            async with self.pool.acquire() as connection:
                self.stats.checked_out += 1
                self.stats.peak_connections = max(self.stats.peak_connections, self.stats.checked_out)
                
                if query.strip().upper().startswith('SELECT'):
                    result = await connection.fetch(query, *args, **kwargs)
                    rows_affected = len(result)
                else:
                    result = await connection.execute(query, *args, **kwargs)
                    # Parse rows affected from result if available
                    if isinstance(result, str) and result.startswith(('INSERT', 'UPDATE', 'DELETE')):
                        parts = result.split()
                        if len(parts) > 1:
                            try:
                                rows_affected = int(parts[1])
                            except ValueError:
                                pass
                
                self.stats.checked_out -= 1
                self.stats.checked_in += 1
                self.stats.total_queries_executed += 1
                
                return result
                
        except Exception as e:
            success = False
            error_message = str(e)
            logger.error(f"Query execution failed: {e}")
            raise
        
        finally:
            execution_time = time.time() - start_time
            
            # Update average query time
            total_time = self.stats.average_query_time * (self.stats.total_queries_executed - 1)
            self.stats.average_query_time = (total_time + execution_time) / self.stats.total_queries_executed
            
            # Record query metrics
            metrics = QueryMetrics(
                query_hash=query_hash,
                query_text=query,
                execution_time=execution_time,
                timestamp=datetime.now(),
                rows_affected=rows_affected,
                database=self.stats.pool_name,
                success=success,
                error_message=error_message
            )
            
            self.query_optimizer.record_query(metrics)
    
    async def execute_transaction(self, queries: List[str], *args, **kwargs) -> List[Any]:
        """Execute multiple queries in a transaction"""
        if not self.pool:
            raise RuntimeError("Connection pool not initialized")
        
        results = []
        
        async with self.pool.acquire() as connection:
            async with connection.transaction():
                for query in queries:
                    result = await self.execute_query(query, *args, **kwargs)
                    results.append(result)
        
        return results
    
    def get_pool_stats(self) -> ConnectionPoolStats:
        """Get current pool statistics"""
        if self.pool:
            self.stats.size = self.pool.get_size()
            self.stats.checked_in = self.pool.get_idle_size()
            # checked_out is maintained in execute_query
        
        return self.stats

class RedisConnectionPool:
    """Redis connection pool for caching and session management"""
    
    def __init__(self, redis_url: str, config: Dict[str, Any] = None):
        self.redis_url = redis_url
        self.config = config or {}
        self.pool: Optional[redis.ConnectionPool] = None
        self.redis: Optional[redis.Redis] = None
        
    async def initialize(self):
        """Initialize Redis connection pool"""
        try:
            self.pool = redis.ConnectionPool.from_url(
                self.redis_url,
                max_connections=self.config.get('max_connections', 20),
                retry_on_timeout=True,
                health_check_interval=30
            )

            self.redis = redis.Redis(connection_pool=self.pool)

            # Test connection
            await self.redis.ping()

            logger.info("Redis connection pool initialized")

        except Exception as e:
            logger.error(f"Failed to initialize Redis connection pool: {e}")
            raise
    
    async def close(self):
        """Close Redis connection pool"""
        if self.redis:
            await self.redis.close()
        if self.pool:
            await self.pool.disconnect()
        logger.info("Redis connection pool closed")
    
    async def get(self, key: str) -> Optional[str]:
        """Get value from Redis"""
        if not self.redis:
            return None
        
        try:
            return await self.redis.get(key)
        except Exception as e:
            logger.error(f"Redis GET error: {e}")
            return None
    
    async def set(self, key: str, value: str, ttl: int = None) -> bool:
        """Set value in Redis"""
        if not self.redis:
            return False
        
        try:
            if ttl:
                await self.redis.setex(key, ttl, value)
            else:
                await self.redis.set(key, value)
            return True
        except Exception as e:
            logger.error(f"Redis SET error: {e}")
            return False
    
    async def delete(self, key: str) -> bool:
        """Delete key from Redis"""
        if not self.redis:
            return False
        
        try:
            result = await self.redis.delete(key)
            return result > 0
        except Exception as e:
            logger.error(f"Redis DELETE error: {e}")
            return False

class DatabaseOptimizer:
    """Main database optimization coordinator"""
    
    def __init__(self, config: Dict[str, Any] = None):
        self.config = config or {}
        self.connection_pools: Dict[str, AsyncConnectionPool] = {}
        self.redis_pools: Dict[str, RedisConnectionPool] = {}
        self.running = False
        self.optimization_task = None
        
    async def start(self):
        """Start database optimization"""
        # Initialize connection pools
        for pool_name, pool_config in self.config.get('database_pools', {}).items():
            pool = AsyncConnectionPool(pool_config['url'], pool_config)
            await pool.initialize()
            self.connection_pools[pool_name] = pool
        
        # Initialize Redis pools
        for pool_name, pool_config in self.config.get('redis_pools', {}).items():
            pool = RedisConnectionPool(pool_config['url'], pool_config)
            await pool.initialize()
            self.redis_pools[pool_name] = pool
        
        # Start optimization task
        self.running = True
        self.optimization_task = asyncio.create_task(self._optimization_loop())
        
        logger.info("Database optimizer started")
    
    async def stop(self):
        """Stop database optimization"""
        self.running = False
        
        if self.optimization_task:
            self.optimization_task.cancel()
            try:
                await self.optimization_task
            except asyncio.CancelledError:
                pass
        
        # Close all connection pools
        for pool in self.connection_pools.values():
            await pool.close()
        
        for pool in self.redis_pools.values():
            await pool.close()
        
        logger.info("Database optimizer stopped")
    
    async def _optimization_loop(self):
        """Main optimization loop"""
        while self.running:
            try:
                # Analyze and optimize each pool
                for pool_name, pool in self.connection_pools.items():
                    await self._optimize_pool(pool_name, pool)
                
                # Sleep before next optimization cycle
                await asyncio.sleep(self.config.get('optimization_interval', 300))  # 5 minutes
                
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error in database optimization loop: {e}")
                await asyncio.sleep(60)
    
    async def _optimize_pool(self, pool_name: str, pool: AsyncConnectionPool):
        """Optimize a specific connection pool"""
        stats = pool.get_pool_stats()
        
        # Check for optimization opportunities
        if stats.average_query_time > 1.0:
            logger.warning(f"High average query time in pool '{pool_name}': {stats.average_query_time:.3f}s")
        
        if stats.checked_out / stats.size > 0.8:
            logger.warning(f"High connection utilization in pool '{pool_name}': {stats.checked_out}/{stats.size}")
        
        # Get query optimization suggestions
        suggestions = pool.query_optimizer.suggest_optimizations()
        if suggestions:
            logger.info(f"Optimization suggestions for pool '{pool_name}': {suggestions}")
    
    def get_pool(self, name: str = 'default') -> Optional[AsyncConnectionPool]:
        """Get a database connection pool"""
        return self.connection_pools.get(name)
    
    def get_redis_pool(self, name: str = 'default') -> Optional[RedisConnectionPool]:
        """Get a Redis connection pool"""
        return self.redis_pools.get(name)
    
    def get_optimization_report(self) -> Dict[str, Any]:
        """Generate comprehensive database optimization report"""
        report = {
            'database_pools': {},
            'redis_pools': {},
            'overall_recommendations': []
        }
        
        # Database pool statistics
        for pool_name, pool in self.connection_pools.items():
            stats = pool.get_pool_stats()
            query_stats = pool.query_optimizer.get_query_statistics()
            
            report['database_pools'][pool_name] = {
                'connection_stats': {
                    'size': stats.size,
                    'checked_out': stats.checked_out,
                    'utilization': stats.checked_out / stats.size if stats.size > 0 else 0,
                    'peak_connections': stats.peak_connections,
                    'total_queries': stats.total_queries_executed,
                    'average_query_time': stats.average_query_time
                },
                'query_stats': query_stats,
                'slow_queries': len(pool.query_optimizer.get_slow_queries(hours=24)),
                'optimization_suggestions': pool.query_optimizer.suggest_optimizations()
            }
        
        # Redis pool statistics
        for pool_name, pool in self.redis_pools.items():
            # Redis doesn't have built-in stats like PostgreSQL pools
            # You would need to implement custom metrics collection
            report['redis_pools'][pool_name] = {
                'status': 'active' if pool.redis else 'inactive'
            }
        
        # Overall recommendations
        total_slow_queries = sum(
            len(pool.query_optimizer.get_slow_queries(hours=24)) 
            for pool in self.connection_pools.values()
        )
        
        if total_slow_queries > 10:
            report['overall_recommendations'].append(
                f"Found {total_slow_queries} slow queries across all pools - consider database optimization"
            )
        
        high_utilization_pools = [
            name for name, pool in self.connection_pools.items()
            if pool.get_pool_stats().checked_out / pool.get_pool_stats().size > 0.8
        ]
        
        if high_utilization_pools:
            report['overall_recommendations'].append(
                f"High connection utilization in pools: {', '.join(high_utilization_pools)} - consider increasing pool size"
            )
        
        return report

# SQLAlchemy event listeners for query monitoring
@event.listens_for(Engine, "before_cursor_execute")
def receive_before_cursor_execute(conn, cursor, statement, parameters, context, executemany):
    context._query_start_time = time.time()

@event.listens_for(Engine, "after_cursor_execute")
def receive_after_cursor_execute(conn, cursor, statement, parameters, context, executemany):
    total = time.time() - context._query_start_time
    
    # Log slow queries
    if total > 1.0:  # 1 second threshold
        logger.warning(f"Slow SQLAlchemy query: {total:.3f}s - {statement[:100]}...")

# Utility functions for database optimization
async def analyze_table_performance(pool: AsyncConnectionPool, table_name: str) -> Dict[str, Any]:
    """Analyze performance of a specific table"""
    queries = [
        f"SELECT COUNT(*) as row_count FROM {table_name}",
        f"SELECT pg_size_pretty(pg_total_relation_size('{table_name}')) as table_size",
        f"SELECT schemaname, tablename, attname, n_distinct, correlation FROM pg_stats WHERE tablename = '{table_name}'"
    ]
    
    results = {}
    
    for query in queries:
        try:
            result = await pool.execute_query(query)
            results[query] = result
        except Exception as e:
            logger.error(f"Error analyzing table {table_name}: {e}")
            results[query] = None
    
    return results

async def suggest_indexes(pool: AsyncConnectionPool, table_name: str) -> List[str]:
    """Suggest indexes for a table based on query patterns"""
    # This is a simplified example - in practice, you'd analyze query logs
    suggestions = []
    
    try:
        # Get columns that might benefit from indexes
        query = f"""
        SELECT column_name, data_type 
        FROM information_schema.columns 
        WHERE table_name = '{table_name}'
        AND data_type IN ('integer', 'bigint', 'uuid', 'timestamp', 'varchar')
        """
        
        result = await pool.execute_query(query)
        
        for row in result:
            column_name = row['column_name']
            if column_name.endswith('_id') or column_name in ['created_at', 'updated_at', 'email']:
                suggestions.append(f"CREATE INDEX idx_{table_name}_{column_name} ON {table_name} ({column_name});")
    
    except Exception as e:
        logger.error(f"Error suggesting indexes for {table_name}: {e}")
    
    return suggestions

