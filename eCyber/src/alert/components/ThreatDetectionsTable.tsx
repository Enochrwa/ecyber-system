
import React from "react";
import DataTable from "./DataTable";
import { ThreatDetection, Alert } from "@/types"; // Assuming Alert is a more generic type from types.ts
import { Badge } from "@/components/ui/badge";
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from "@/components/ui/tooltip";
import { getSeverityConfig, getTypeConfig, formatAlertTimestamp, displayValue } from "../lib/config";
import { cn } from "@/lib/utils";

interface ThreatDetectionsTableProps {
  // Use a more generic Alert type if ThreatDetection is too specific or lacks common fields
  threats: Alert[]; 
  className?: string;
}

const ThreatDetectionsTable = ({ threats, className }: ThreatDetectionsTableProps) => {
  const columns = [
    {
      key: "severity",
      header: "Severity",
      cell: (item: Alert) => {
        const config = getSeverityConfig(item.severity);
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
      key: "threat_type", // Assuming 'threat_type' field exists on Alert
      header: "Type",
      cell: (item: Alert) => {
        // Try to infer a more specific type if possible, otherwise use a generic 'threat'
        const typeKey = item.threat_type || (item.type ? String(item.type) : 'threat');
        const config = getTypeConfig(typeKey);
        return (
          <span className={cn("flex items-center", config.color)}>
            <config.icon className="w-4 h-4 mr-1.5" />
            {config.label}
          </span>
        );
      },
      sortable: true,
    },
    {
      key: "description", // Renamed from message for consistency if Alert uses description
      header: "Description",
      cell: (item: Alert) => (
        <TooltipProvider>
          <Tooltip>
            <TooltipTrigger>
              <span className="truncate block max-w-xs">{displayValue(item.description || item.message)}</span>
            </TooltipTrigger>
            <TooltipContent>
              <p>{displayValue(item.description || item.message)}</p>
            </TooltipContent>
          </Tooltip>
        </TooltipProvider>
      ),
      sortable: true,
    },
    {
      key: "source_ip",
      header: "Source IP",
      cell: (item: Alert) => <span className="font-mono text-xs">{displayValue(item.source_ip)}</span>,
      sortable: true,
    },
    {
      key: "destination_ip", // Added destination IP
      header: "Destination IP",
      cell: (item: Alert) => <span className="font-mono text-xs">{displayValue(item.destination_ip)}</span>,
      sortable: true,
    },
    {
      key: "protocol", // Added protocol
      header: "Protocol",
      cell: (item: Alert) => <span className="text-xs">{displayValue(item.protocol)}</span>,
      sortable: true,
    },
    {
      key: "timestamp",
      header: "Timestamp",
      cell: (item: Alert) => <span>{formatAlertTimestamp(item.timestamp)}</span>,
      sortable: true,
    },
    {
      key: "rule_id", // Assuming rule_id might be part of metadata or a direct field
      header: "Rule ID",
      cell: (item: Alert) => <span className="text-xs bg-muted px-1.5 py-0.5 rounded">{displayValue(item.rule_id || item.metadata?.rule_id)}</span>,
      sortable: true,
    },
    // Example for mitigation status if it's part of the Alert type
    // {
    //   key: "mitigationStatus",
    //   header: "Mitigation",
    //   cell: (item: Alert) => (
    //     item.metadata?.mitigationStatus ? (
    //       <span className={`inline-flex px-2 py-1 rounded-full text-xs ${
    //         item.metadata.mitigationStatus === "Auto-mitigated" 
    //           ? "bg-green-100 text-green-700" 
    //           : "bg-yellow-100 text-yellow-700"
    //       }`}>
    //         {displayValue(item.metadata.mitigationStatus)}
    //       </span>
    //     ) : displayValue(null)
    //   ),
    //   sortable: true,
    // },
  ];

  return (
    <DataTable columns={columns} data={threats} className={className} />
  );
};

export default ThreatDetectionsTable;
