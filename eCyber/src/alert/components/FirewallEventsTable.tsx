
import React from "react";
import DataTable from "./DataTable";
import { FirewallEvent, Alert } from "@/types"; // Assuming FirewallEvent might extend a base Alert type or has similar fields
import { Badge } from "@/components/ui/badge";
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from "@/components/ui/tooltip";
import { getSeverityConfig, getTypeConfig, formatAlertTimestamp, displayValue } from "../lib/config";
import { cn } from "@/lib/utils";

interface FirewallEventsTableProps {
  events: FirewallEvent[]; // Or Alert[] if FirewallEvent properties are merged into Alert
  className?: string;
}

const FirewallEventsTable = ({ events, className }: FirewallEventsTableProps) => {
  const columns = [
    {
      key: "severity",
      header: "Severity",
      cell: (event: FirewallEvent) => {
        // Infer severity: 'Blocked' is high, 'Allowed' could be info/low.
        // Or use event.severity if available from backend.
        const severityStr = event.severity || (event.action === "Blocked" ? 'high' : 'info');
        const config = getSeverityConfig(severityStr);
        return (
          <Badge variant="outline" className={cn("border", config.borderColor, config.bgColor, config.textColor)}>
            <config.icon className={cn("w-3.5 h-3.5 mr-1.5", config.textColor)} />
            {config.label}
          </Badge>
        );
      },
      sortable: true,
    },
    {
      key: "action",
      header: "Action",
      cell: (event: FirewallEvent) => {
        const typeKey = event.action === "Blocked" ? "firewall_block" : "firewall_allow";
        const config = getTypeConfig(typeKey);
        return (
          <span className={cn("flex items-center font-medium", config.color)}>
            <config.icon className="w-4 h-4 mr-1.5" />
            {displayValue(event.action)}
          </span>
        );
      },
      sortable: true,
    },
    {
      key: "source_ip", // Assuming source_ip is preferred over ipAddress for consistency
      header: "Source IP",
      cell: (event: FirewallEvent) => (
        <span className="font-mono text-xs">{displayValue(event.source_ip || event.ipAddress)}</span>
      ),
      sortable: true,
    },
    {
      key: "destination_ip",
      header: "Destination IP",
      cell: (event: FirewallEvent) => (
        <span className="font-mono text-xs">{displayValue(event.destination_ip)}</span>
      ),
      sortable: true,
    },
    {
      key: "destination_port",
      header: "Port",
      cell: (event: FirewallEvent) => <span className="text-xs">{displayValue(event.destination_port)}</span>,
      sortable: true,
    },
    {
      key: "protocol",
      header: "Protocol",
      cell: (event: FirewallEvent) => <span className="text-xs">{displayValue(event.protocol)}</span>,
      sortable: true,
    },
    {
      key: "reason",
      header: "Reason",
      cell: (event: FirewallEvent) => (
        <TooltipProvider>
          <Tooltip>
            <TooltipTrigger>
              <span className="truncate block max-w-xs">{displayValue(event.reason)}</span>
            </TooltipTrigger>
            <TooltipContent>
              <p>{displayValue(event.reason)}</p>
            </TooltipContent>
          </Tooltip>
        </TooltipProvider>
      ),
      sortable: true,
    },
    {
      key: "rule_id", // Renamed from ruleTrigger for consistency
      header: "Rule ID",
      cell: (event: FirewallEvent) => (
        <Badge variant="secondary" className="text-xs">{displayValue(event.rule_id || event.ruleTrigger)}</Badge>
      ),
      sortable: true,
    },
    // geoLocation might be better handled by GeoIP lookup on source_ip if needed
    // {
    //   key: "geoLocation",
    //   header: "Geo-location",
    //   cell: (event: FirewallEvent) => <span>{displayValue(event.geoLocation)}</span>,
    //   sortable: true,
    // },
    {
      key: "timestamp",
      header: "Timestamp",
      cell: (event: FirewallEvent) => <span>{formatAlertTimestamp(event.timestamp)}</span>,
      sortable: true,
    },
  ];

  return (
    <DataTable columns={columns} data={events} className={className} />
  );
};

export default FirewallEventsTable;
