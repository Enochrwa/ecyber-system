import logging
import warnings

from typing import Optional

from scapy.packet import Packet
from scapy.sessions import DefaultSession
from cicflowmeter.writer import output_writer_factory, CSVWriter  # CSVWriter for type check
from .constants import EXPIRED_UPDATE, PACKETS_PER_GC
from .features.context import PacketDirection, get_packet_flow_key
from .flow import Flow
from .utils import get_logger

# Suppress warnings
from cryptography.utils import CryptographyDeprecationWarning
warnings.filterwarnings("ignore", category=CryptographyDeprecationWarning)
warnings.filterwarnings("ignore", category=UserWarning)
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)


class FlowSession(DefaultSession):
    """Creates a list of network flows and exports them to CSV or memory."""

    def __init__(
        self,
        output_mode: Optional[str] = None,
        output: Optional[str] = None,
        fields: Optional[list] = None,
        verbose: bool = False,
        *args,
        **kwargs
    ):
        self.flows: dict[tuple, Flow] = {}
        self.verbose = verbose
        self.fields = fields
        self.output_mode = output_mode
        self.output = output
        self.logger = get_logger(self.verbose)
        self.packets_count = 0

        # ✅ Always instantiate a writer (even if output=None)
        self.output_writer = output_writer_factory(self.output_mode or "csv", self.output)

        super().__init__(*args, **kwargs)

    def __getstate__(self):
        state = self.__dict__.copy()
        state.pop("output_writer", None)
        return state

    def __setstate__(self, state):
        self.__dict__.update(state)
        if self.output_mode:
            self.output_writer = output_writer_factory(self.output_mode, self.output)
        else:
            self.output_writer = None

    def process(self, pkt: Packet):
        if "TCP" not in pkt and "UDP" not in pkt:
            return None

        self.logger.debug(f"Packet {self.packets_count}: {pkt}")
        direction = PacketDirection.FORWARD

        try:
            packet_flow_key = get_packet_flow_key(pkt, direction)
            flow = self.flows.get((packet_flow_key, 0))
        except Exception:
            return None

        self.packets_count += 1

        if flow is None:
            direction = PacketDirection.REVERSE
            packet_flow_key = get_packet_flow_key(pkt, direction)
            flow = self.flows.get((packet_flow_key, 0))

        if flow is None:
            direction = PacketDirection.FORWARD
            flow = Flow(pkt, direction)
            packet_flow_key = get_packet_flow_key(pkt, direction)
            self.flows[(packet_flow_key, 0)] = flow
        elif (pkt.time - flow.latest_timestamp) > EXPIRED_UPDATE:
            expired = EXPIRED_UPDATE
            count = 1
            while (pkt.time - flow.latest_timestamp) > expired:
                expired += EXPIRED_UPDATE
                flow = self.flows.get((packet_flow_key, count))
                if flow is None:
                    flow = Flow(pkt, direction)
                    self.flows[(packet_flow_key, count)] = flow
                    break
                count += 1
        elif "F" in pkt.flags:
            flow.add_packet(pkt, direction)
            self.garbage_collect(pkt.time)
            return None

        flow.add_packet(pkt, direction)

        if self.packets_count % PACKETS_PER_GC == 0 or flow.duration > 120:
            self.garbage_collect(pkt.time)

        return None

    def garbage_collect(self, latest_time: Optional[float]) -> None:
        for k in list(self.flows.keys()):
            flow = self.flows.get(k)
            if not flow:
                continue

            if (
                latest_time is not None
                and latest_time - flow.latest_timestamp < EXPIRED_UPDATE
                and flow.duration < 90
            ):
                continue

            self.output_writer.write(flow.get_data(self.fields))
            del self.flows[k]
            self.logger.debug(f"Flow collected. Remaining = {len(self.flows)}")

    def flush_flows(self, return_dataframe: bool = False) -> Optional["pd.DataFrame"]:
        for flow in list(self.flows.values()):
            self.output_writer.write(flow.get_data(self.fields))
        self.flows.clear()

        # ✅ Only return DataFrame if using in-memory mode
        if return_dataframe and isinstance(self.output_writer, CSVWriter):
            try:
                return self.output_writer.to_dataframe()
            except Exception as e:
                self.logger.warning(f"Unable to return DataFrame: {e}")
        return None

    def get_flows(self):
        return list(self.flows.values())

    def toPacketList(self):
        self.garbage_collect(None)
        return super().toPacketList()
