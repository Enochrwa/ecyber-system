from contextlib import asynccontextmanager
from datetime import datetime
import time
import asyncio
import logging
import time
import os
from scapy.all import get_if_list
from fastapi.middleware.httpsredirect import HTTPSRedirectMiddleware
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
import socketio
from multiprocessing import Queue, Manager
import multiprocessing
from queue import Full, Empty
import asyncio
import psutil

# Configuration
from app.core.config import settings

# from app.middleware.blocker_middleware import BlocklistMiddleware
from app.api.v1.api import api_v1_router

# from app.api.v1.endpoints.threats import router as threat_router_v1
# from app.services.prevention.app_blocker import ApplicationBlocker
from app.core.logger import setup_logger
from socket_events import get_socket_app
from app.services.system.monitor import SystemMonitor

# from app.services.detection.phishing_blocker import PhishingBlocker

# from app.services.system.malware_detection import activate_cyber_defense

# SIEM Integration
from app.api.siem_api import initialize_siem_manager, router as siem_router
from app.services.siem.siem_integration import SIEMManager

# Performance Optimization
from app.services.performance.optimizer import PerformanceOptimizer
from app.services.performance.database_optimizer import DatabaseOptimizer

# Database
from sqlalchemy.ext.asyncio import AsyncEngine
from app.database import engine, Base, AsyncSessionLocal, init_db


# Routers
from app.api import (
    users as user_router,
    network as network_router,
    auth as auth_router,
    threats as threat_router,
    models as ml_models_router,
    system as system_router,
    admin as admin_router,
)
from app.api.v1.endpoints.threats import router as ml_threats
from api.firewall_api import router as firewall_router
from api.threat_intel_api import router as intel_router
from api.nac_api import router as nac_router
from api.dns_api import router as dns_router
from api.ml_models_api import router as ml_models_api_router  # Added for ML models API
from app.utils.report import (
    get_24h_network_traffic,
    get_daily_threat_summary,
    handle_network_history,
)

# from app.api.ips import get_ips_engine

# Services
from app.services.monitoring.sniffer import PacketSniffer
from app.services.detection.signature import SignatureEngine

# from app.services.detection.ids_signature import IdsSignatureEngine
from app.services.ips.engine import EnterpriseIPS, ThreatIntel

# Enhanced Security Components
from app.services.ips.enhanced_blocker import EnhancedIPBlocker
from app.services.ips.signature_detection import AdvancedSignatureEngine
from app.services.ips.phishing_blocker import AdvancedPhishingBlocker

# from app.services.ips.adapter import IPSPacketAdapter
from app.services.prevention.firewall import FirewallManager

# from app.services.tasks.autofill_task import run_autofill_task

# Socket.IO
from sio_instance import sio
from packet_sniffer_service import PacketSnifferService
from packet_sniffer_events import PacketSnifferNamespace
from malware_events_namespace import MalwareEventsNamespace  # Add this

# from socket_events import start_event_emitter

# Logging setup
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
setup_logger("main", "INFO")
logger = logging.getLogger(__name__)

manager = None
sniffer = None
sniffer_service = None
startup_start_time = time.time()
server_ready_emitted = False

# Enhanced Security Components
enhanced_ip_blocker = None
signature_engine = None
phishing_blocker = None

###VULNERABILITY
# scanner = VulnerabilityScanner(sio)
# val_blocker = ThreatBlocker(sio)


async def create_app() -> FastAPI:
    """Create and configure the FastAPI application."""
    # Initialize FastAPI app first
    app = FastAPI(
        title=settings.PROJECT_NAME,
        docs_url="/api/docs" if settings.DOCS else None,
        redoc_url=None,
    )

    # Initialize database
    try:
        if isinstance(engine, AsyncEngine):
            async with engine.begin() as conn:
                await conn.run_sync(Base.metadata.create_all)
            logger.info("Database initialized successfully")
        else:
            raise RuntimeError("Database engine is not asynchronous")
    except Exception as e:
        logger.critical(f"Database initialization failed: {str(e)}")
        raise

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        """Lifespan for startup and shutdown events."""
        await init_db()
        logger.info("🚀 Starting eCyber Security System")
        logger.info("Initializing background services...")

        # Initialize services
        firewall = FirewallManager(sio)
        signature_engine = SignatureEngine(sio)
        # ids_signature_engine = IdsSignatureEngine(sio)
        # blocker = ApplicationBlocker(sio)

        # Initialize Enhanced Security Components
        global enhanced_ip_blocker, advanced_sig_engine, phishing_blocker
        
        # Enhanced IP Blocker
        enhanced_ip_blocker = EnhancedIPBlocker({
            'db_path': 'data/blocked_ips.db',
            'vlan_isolation_enabled': True
        })
        await enhanced_ip_blocker.start()
        logger.info("Enhanced IP Blocker initialized")
        
        # Advanced Signature Engine
        advanced_sig_engine = AdvancedSignatureEngine({
            'signature_db_path': 'data/signatures.db',
            'signature_sources': [
                {
                    'type': 'custom_json',
                    'url': 'https://raw.githubusercontent.com/emergingthreats/rules/master/rules/emerging-threats.json',
                    'source': 'emerging_threats'
                }
            ],
            'update_interval': 3600
        })
        await advanced_sig_engine.start()
        logger.info("Advanced Signature Engine initialized")
        
        # Advanced Phishing Blocker
        phishing_blocker = AdvancedPhishingBlocker({
            'phishing_db_path': 'data/phishing.db',
            'threat_feeds': [
                {
                    'type': 'text',
                    'url': 'https://openphish.com/feed.txt',
                    'source': 'openphish'
                }
            ],
            'update_interval': 1800,
            'content_analysis_enabled': True,
            'block_threshold': 0.7
        })
        await phishing_blocker.start()
        logger.info("Advanced Phishing Blocker initialized")

        # Initialize SIEM Integration
        global siem_manager
        siem_config = {
            'elasticsearch': {
                'elasticsearch_hosts': ['localhost:9200'],
                'username': None,
                'password': None,
                'use_ssl': False,
                'verify_certs': False,
                'index_prefix': 'aurore-siem',
                'batch_size': 100,
                'flush_interval': 30
            },
            'kibana': {
                'kibana_url': 'http://localhost:5601',
                'username': None,
                'password': None,
                'space_id': 'default'
            }
        }
        
        try:
            siem_manager = initialize_siem_manager(siem_config)
            await siem_manager.start()
            logger.info("SIEM Integration initialized successfully")
        except Exception as e:
            logger.warning(f"SIEM Integration failed to start: {e}")
            logger.warning("Continuing without SIEM - install Elasticsearch and Kibana for full functionality")

        # Initialize Performance Optimization
        global performance_optimizer, database_optimizer
        
        performance_config = {
            'monitoring': {
                'monitoring_interval': 30,
                'history_size': 1000,
                'cpu_threshold': 80.0,
                'memory_threshold': 85.0,
                'disk_threshold': 90.0
            }
        }
        
        database_config = {
            'optimization_interval': 300,  # 5 minutes
            'database_pools': {
                'default': {
                    'url': settings.SQLALCHEMY_DATABASE_URL, # <-- This line needs to change
                    'min_size': 5,
                    'max_size': 20,
                    'max_queries': 50000,
                    'max_inactive_connection_lifetime': 300,
                    'query_optimizer': {
                        'slow_query_threshold': 1.0
                    }
                }
            },
            'redis_pools': {
                'default': {
                    'url': getattr(settings, 'REDIS_URL', 'redis://localhost:6379'),
                    'max_connections': 20
                }
            }
        }
        
        try:
            performance_optimizer = PerformanceOptimizer(performance_config)
            await performance_optimizer.start()
            logger.info("Performance optimizer initialized successfully")
            
            database_optimizer = DatabaseOptimizer(database_config)
            await database_optimizer.start()
            logger.info("Database optimizer initialized successfully")
            
        except Exception as e:
            logger.warning(f"Performance optimization failed to start: {e}")
            logger.warning("Continuing without performance optimization")

        # Initialize packet components INDEPENDENTLY
        global sniffer, sniffer_service, manager
        manager = Manager()
        sio_queue = manager.Queue(maxsize=10000)
        output_queue = Queue()
        # ips_queue = manager.Queue(maxsize=10000)
        sniffer_namespace = PacketSnifferNamespace("/packet_sniffer", sio_queue)
        sio.register_namespace(sniffer_namespace)

        malware_events_ns = MalwareEventsNamespace("/malware_events")
        sio.register_namespace(malware_events_ns)
        logger.info("Registered /malware_events namespace for EMPDRS communication.")

        intel = ThreatIntel()
        await intel.load_from_cache()
        asyncio.create_task(intel.fetch_and_cache_feeds())
        rules_path = os.path.join(os.path.dirname(__file__), "rules.json")
        num_workers=min(8, multiprocessing.cpu_count())
        ips = EnterpriseIPS(
            rules_path,
            sio,
            intel,
            num_workers,
            sio_queue,
            output_queue,
            enhanced_ip_blocker=enhanced_ip_blocker,
            signature_engine=advanced_sig_engine,
            phishing_blocker=phishing_blocker,
            siem_manager=siem_manager
        )

        sniffer = PacketSniffer(sio_queue)

        sniffer_service = PacketSnifferService(sio, sio_queue)

        # loop = asyncio.get_event_loop()  # Get current loop
        monitor = SystemMonitor(sio)
        # cyber_defender = activate_cyber_defense(monitor)

        # phishing_blocker = PhishingBlocker(sio)
        # logger.info("PhishingBlocker initialized.")

        # Initialize IPS Adapter
        # ips_adapter = IPSPacketAdapter(ips)
        # await ips_adapter.start()

        # Start database autofill task
        # autofill_task = asyncio.create_task(run_autofill_task(interval=300))

        # Store services in app state

        app.state.firewall = firewall
        app.state.signature_engine = signature_engine
        app.state.enhanced_ip_blocker = enhanced_ip_blocker
        app.state.advanced_signature_engine = advanced_sig_engine
        app.state.phishing_blocker = phishing_blocker
        # app.state.ids_signature_engine = ids_signature_engine
        # app.state.phishing_blocker = (
        #     phishing_blocker  # Store PhishingBlocker in app state
        # )
        # app.state.ips_engine = ips
        # app.state.ips_adapter = ips_adapter
        app.state.db = AsyncSessionLocal
        # app.state.autofill_task = autofill_task
        # app.state.blocker = blocker

        # emitter_task = asyncio.create_task(start_event_emitter())  # Pass the factory
        # app.state.emitter_task = emitter_task

        try:
            # loop = asyncio.get_running_loop()
            # await loop.run_in_executor(None, sniffer.start, "Wi-Fi"
            await sniffer_service.start()
            await sniffer.start("enp0s8")
            await monitor.start()
            await ips.start()
            logger.info("System monitoring started")
            # Start packet sniffer with IPS integration

            # Start IPS updates task
            # asyncio.create_task(ips_updates_task(ips))

            # Emit periodic summary
            @sio.on("request_daily_summary")
            async def _on_request_summary(sid):
                try:
                    if not monitor.data_queue.empty():
                        stats = monitor.data_queue.get_nowait()
                        net24 = get_24h_network_traffic(stats)
                        threats = get_daily_threat_summary(monitor)
                        await sio.emit(
                            "daily_summary",
                            {"network24h": net24, "threatSummary": threats},
                            to=sid,
                        )
                except Empty:
                    pass

            yield

        finally:
            # Shutdown tasks
            logger.info("🛑 Gracefully shutting down...")
            if sniffer_service:
                sniffer_service.stop()
            if sniffer:
                sniffer.stop()
            # Shutdown enhanced security components
            if enhanced_ip_blocker:
                await enhanced_ip_blocker.stop()
                logger.info("Enhanced IP Blocker stopped")
            
            if advanced_sig_engine:
                await advanced_sig_engine.stop()
                logger.info("Advanced Signature Engine stopped")
            
            if phishing_blocker:
                await phishing_blocker.stop()
                logger.info("Advanced Phishing Blocker stopped")
            
            # Shutdown SIEM Integration
            if siem_manager:
                await siem_manager.stop()
                logger.info("SIEM Integration stopped")
            
            # Shutdown Performance Optimization
            if performance_optimizer:
                await performance_optimizer.stop()
                logger.info("Performance optimizer stopped")
            
            if database_optimizer:
                await database_optimizer.stop()
                logger.info("Database optimizer stopped")

            # if hasattr(app.state, "phishing_blocker") and app.state.phishing_blocker:
            #     logger.info("Stopping PhishingBlocker...")
            #     # PhishingBlocker.stop() is an async method
            #     await app.state.phishing_blocker.stop()
            #     logger.info("PhishingBlocker stopped.")

            if monitor:
                await monitor.stop()

            # await ips_adapter.stop()
            # autofill_task.cancel()
            await engine.dispose()  # Dispose DB engine
            if ips:  # ips.stop() is async
                await ips.stop()

    # Set the lifespan after app creation
    app.router.lifespan_context = lifespan

    # Configure CORS first to ensure frontend access
    app.add_middleware(
        CORSMiddleware,
        allow_origins=[
            "http://localhost:3000",
            "http://127.0.0.1:3000",
            "http://localhost:4000",
            "http://127.0.0.1:4000",
            "https://ecyber.vercel.app",
            "https://ecyber-ten.vercel.app"
        ],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # Add other middlewares
    # app.add_middleware(HTTPSRedirectMiddleware)
    # app.add_middleware(
    #     BlocklistMiddleware,
    #     blocker=(
    #         app.state.blocker
    #         if hasattr(app.state, "blocker")
    #         else ApplicationBlocker(sio)
    #     ),
    # )

    # Register routers
    app.include_router(user_router.router, prefix="/api/users", tags=["Users"])
    app.include_router(network_router.router, prefix="/api/network", tags=["Network"])
    app.include_router(auth_router.router, prefix="/api/auth", tags=["Auth"])
    # app.include_router(threat_router_v1, prefix="/api/v1/threats", tags=["Threats"])
    app.include_router(threat_router.router, prefix="/api/threats", tags=["Threats"])
    app.include_router(system_router.router, prefix="/api/system", tags=["System"])
    app.include_router(admin_router.router, prefix="/api/admin", tags=["Admin"])
    app.include_router(api_v1_router, prefix="/api/v1", tags=["APIv1"])
    app.include_router(
        ml_models_router.router, prefix="/api/v1/models", tags=["models"]
    )  # Added for ML models
    # app.include_router(ids_router.router, prefix="/api/ids", tags=["IDS"])
    app.include_router(firewall_router, prefix="/firewall")
    app.include_router(intel_router, prefix="/intel")
    app.include_router(nac_router, prefix="/nac")
    app.include_router(dns_router, prefix="/dns")
    app.include_router(siem_router, prefix="/api", tags=["SIEM"])  # SIEM Integration
    # Include the ML Models API router

    # Health check endpoint
    @app.get("/api/health", include_in_schema=False)
    async def health_check():
        return {"status": "ok"}

    # Mount Socket.IO app
    socket_app = get_socket_app(app)
    app.mount("/socket.io", socket_app)

    return app


# Socket.IO events
@sio.event
async def connect(sid, environ):
    pass
    # interfaces = get_if_list()
    # await sio.emit("interfaces", interfaces, to=sid)
    # PROD_CLEANUP: logger.info(f"Client connected: {sid[:8]}...")


@sio.on("start_sniffing")
async def _on_start_sniffing(sid, data):
    logger.info(f"User started sniffing on {data.get('sniffingInterface')}")
    global sniffer, sniffer_service
    try:
        interface = data.get("sniffingInterface", "enp0s8")
        # if sniffer_service:
        #     sniffer_service.stop()
        # if sniffer:
        #     sniffer.stop()
        # time.sleep(10)
        await sniffer_service.start()
        await sniffer.start(interface)
        await sio.emit("sniffing_started", {"interface": interface}, to=sid)
    except Exception as e:
        logger.error(f"Error starting sniffer: {str(e)}")
        await sio.emit("sniffing_error", {"error": str(e)}, to=sid)


@sio.on("stop_sniffing")
async def _on_stop_sniffing(sid):
    logger.info("User stopped sniffing")
    global sniffer, sniffer_service
    try:
        if sniffer:
            logger.info("Stopping PacketSniffer...")
            sniffer.stop()

            logger.info("PacketSniffer stopped.")
        
        if sniffer_service:
            await sniffer_service.stop()
        await sio.emit("sniffing_stopped", to=sid)
    except Exception as e:
        logger.error(f"Error stopping sniffer: {str(e)}")
        await sio.emit("sniffing_error", {"error": str(e)}, to=sid)


async def emit_progress():
    while not server_ready_emitted:
        elapsed = time.time() - startup_start_time
        await sio.emit("startup_progress", {"elapsed_time": elapsed})
        await asyncio.sleep(0.5)


# Call this AFTER ALL services have started
async def mark_server_ready():
    global server_ready_emitted
    total_time = time.time() - startup_start_time
    await sio.emit("server_ready", {"startup_time": total_time}, namespace="/packet_sniffer")
    server_ready_emitted = True

if __name__ == "__main__":
    import multiprocessing
    multiprocessing.freeze_support() 
    import uvicorn
    import asyncio

    async def run():
        app = await create_app()  # Async FastAPI app creation
        config = uvicorn.Config(app=app, host="127.0.0.1", port=8000, reload=False, loop="asyncio")

        server = uvicorn.Server(config)

        # Start the Uvicorn server and other async tasks
        server_task = asyncio.create_task(server.serve())
        asyncio.create_task(emit_progress())
        await mark_server_ready()

        await server_task

    try:
        asyncio.run(run())
    except KeyboardInterrupt:
        pass
