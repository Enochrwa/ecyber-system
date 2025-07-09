
import React from "react";
import DataTable from "./DataTable";
import { HttpActivity } from "../types";
import { Badge } from "@/components/ui/badge";
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from "@/components/ui/tooltip";
import { getSeverityConfig, formatAlertTimestamp, displayValue, getTypeConfig } from "../lib/config";
import { cn } from "@/lib/utils";
import { ShieldAlert, ShieldCheck, ShieldQuestion } from "lucide-react"; // Example icons for issues

interface HttpActivityTableProps {
  activities: HttpActivity[];
  className?: string;
}

const HttpActivityTable = ({ activities, className }: HttpActivityTableProps) => {

  const getThreatSeverityFromScore = (score: number | undefined): string => {
    if (score === undefined || score === null) return 'unknown';
    if (score >= 80) return 'critical';
    if (score >= 60) return 'high';
    if (score >= 30) return 'medium';
    if (score >= 10) return 'low';
    return 'info';
  };

  const columns = [
    {
      key: "timestamp",
      header: "Timestamp",
      cell: (activity: HttpActivity) => <span>{formatAlertTimestamp(activity.timestamp)}</span>,
      sortable: true,
    },
    {
      key: "severity", // New Severity column
      header: "Severity",
      cell: (activity: HttpActivity) => {
        const severityStr = getThreatSeverityFromScore(activity.threatScore);
        const config = getSeverityConfig(severityStr);
        return (
          <Badge variant="outline" className={cn("border", config.borderColor, config.bgColor, config.textColor)}>
            <config.icon className={cn("w-3.5 h-3.5 mr-1.5", config.textColor)} />
            {config.label}
          </Badge>
        );
      },
      sortable: true,
      // Custom sort method for severity based on score
      sortFn: (a: HttpActivity, b: HttpActivity) => (a.threatScore || 0) - (b.threatScore || 0)
    },
    {
      key: "method",
      header: "Method",
      cell: (activity: HttpActivity) => (
        <Badge variant={activity.method === "GET" ? "secondary" : "default"}>{displayValue(activity.method)}</Badge>
      ),
      sortable: true,
    },
    {
      key: "path",
      header: "Path",
      cell: (activity: HttpActivity) => (
        <TooltipProvider>
          <Tooltip>
            <TooltipTrigger>
              <span className="font-mono text-xs truncate block max-w-[250px]">{displayValue(activity.path)}</span>
            </TooltipTrigger>
            <TooltipContent>
              <p className="font-mono text-xs">{displayValue(activity.path)}</p>
            </TooltipContent>
          </Tooltip>
        </TooltipProvider>
      ),
      sortable: true,
    },
    {
      key: "statusCode",
      header: "Status",
      cell: (activity: HttpActivity) => {
        const status = activity.statusCode;
        let colorClass = "text-gray-600";
        if (status >= 200 && status < 300) colorClass = "text-green-600";
        else if (status >= 300 && status < 400) colorClass = "text-blue-600";
        else if (status >= 400 && status < 500) colorClass = "text-orange-600";
        else if (status >= 500) colorClass = "text-red-600";
        return (
          <Badge variant="outline" className={cn(colorClass, "border-"+colorClass.replace('text-','bg-')+"/30")}>
            {displayValue(status)}
          </Badge>
        );
      },
      sortable: true,
    },
    {
      key: "sourceIp",
      header: "Source IP",
      cell: (activity: HttpActivity) => <span className="font-mono text-xs">{displayValue(activity.sourceIp)}</span>,
      sortable: true,
    },
    {
      key: "destinationIp",
      header: "Destination IP",
      cell: (activity: HttpActivity) => <span className="font-mono text-xs">{displayValue(activity.destinationIp)}</span>,
      sortable: true,
    },
    {
      key: "securityIssues",
      header: "Flags",
      cell: (activity: HttpActivity) => (
        <div className="flex items-center flex-wrap gap-1">
          {activity?.missingSecurityHeaders?.length > 0 && (
            <TooltipProvider>
              <Tooltip>
                <TooltipTrigger>
                  <Badge variant="outline" className="border-yellow-500/50 bg-yellow-100/50 text-yellow-700">
                    <ShieldAlert className="w-3 h-3 mr-1" /> Hdr
                  </Badge>
                </TooltipTrigger>
                <TooltipContent>Missing: {activity.missingSecurityHeaders.join(', ')}</TooltipContent>
              </Tooltip>
            </TooltipProvider>
          )}
          {activity.injectionDetected && (
             <TooltipProvider>
             <Tooltip>
               <TooltipTrigger>
                <Badge variant="destructive" className="bg-red-500/20 text-red-700 border-red-500/50">
                    <ShieldAlert className="w-3 h-3 mr-1" /> Inj
                </Badge>
                </TooltipTrigger>
                <TooltipContent>Potential Injection Detected</TooltipContent>
              </Tooltip>
            </TooltipProvider>
          )}
          {activity.beaconingIndicators && (
            <TooltipProvider>
            <Tooltip>
              <TooltipTrigger>
                <Badge variant="outline" className="border-purple-500/50 bg-purple-100/50 text-purple-700">
                    <Activity className="w-3 h-3 mr-1" /> Bea
                </Badge>
              </TooltipTrigger>
              <TooltipContent>Beaconing Indicators Present</TooltipContent>
            </Tooltip>
          </TooltipProvider>
          )}
          {(!activity?.missingSecurityHeaders?.length && !activity.injectionDetected && !activity.beaconingIndicators) && (
             <ShieldCheck className="w-4 h-4 text-green-500" />
          )}
        </div>
      ),
    },
    {
      key: "threatScore",
      header: "Risk",
      cell: (activity: HttpActivity) => {
        const severityStr = getThreatSeverityFromScore(activity.threatScore);
        const config = getSeverityConfig(severityStr);
        return (
          <div className="flex items-center w-24">
            <div className="h-2.5 w-full bg-muted rounded-full overflow-hidden mr-2 border">
              <div 
                className={cn(`h-full rounded-full`, config.color)}
                style={{ width: `${activity.threatScore || 0}%` }}
              />
            </div>
            <span className={cn("text-xs font-medium", config.textColor)}>
              {displayValue(activity.threatScore, '0')}%
            </span>
          </div>
        );
      },
      sortable: true,
    }
  ];

  return (
    <DataTable columns={columns} data={activities} className={className} />
  );
};

export default HttpActivityTable;
