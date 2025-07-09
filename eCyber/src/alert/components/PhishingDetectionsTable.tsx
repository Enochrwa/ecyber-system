
import React from "react";
import DataTable from "./DataTable";
import { PhishingDetection } from "@/types"; // Assuming PhishingDetection has severity, or we use a more generic Alert type
import { Badge } from "@/components/ui/badge";
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from "@/components/ui/tooltip";
import { getSeverityConfig, getTypeConfig, formatAlertTimestamp, displayValue } from "../lib/config";
import { cn } from "@/lib/utils";

interface PhishingDetectionsTableProps {
  detections: PhishingDetection[];
  className?: string;
}

const PhishingDetectionsTable = ({ detections, className }: PhishingDetectionsTableProps) => {
  const columns = [
    {
      key: "severity", // Assuming PhishingDetection type will be updated or has severity
      header: "Severity",
      cell: (detection: PhishingDetection) => {
        const severityStr = detection.severity || (detection.confidenceScore > 80 ? 'high' : detection.confidenceScore > 60 ? 'medium' : 'low');
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
      key: "url",
      header: "Detected URL",
      cell: (detection: PhishingDetection) => (
        <TooltipProvider>
          <Tooltip>
            <TooltipTrigger>
              <span className="text-xs font-mono break-all truncate block max-w-md">{displayValue(detection.url)}</span>
            </TooltipTrigger>
            <TooltipContent>
              <p>{displayValue(detection.url)}</p>
            </TooltipContent>
          </Tooltip>
        </TooltipProvider>
      ),
      sortable: true,
    },
    {
      key: "confidenceScore",
      header: "Confidence",
      cell: (detection: PhishingDetection) => (
        <div className="flex items-center">
          <div className="h-2 w-full max-w-20 bg-muted rounded-full overflow-hidden mr-2">
            <div 
              className="h-full bg-orange-500" // Use a consistent color or map to severity
              style={{ width: `${detection.confidenceScore || 0}%` }}
            />
          </div>
          <span className="text-xs">{displayValue(detection.confidenceScore?.toFixed(1) || 0)}%</span>
        </div>
      ),
      sortable: true,
    },
    {
      key: "categories",
      header: "Categories",
      cell: (detection: PhishingDetection) => (
        <div className="flex flex-wrap gap-1">
          {(detection.categories || []).map((category, index) => {
            const typeConfig = getTypeConfig(category.toLowerCase()); // Try to map category to a type
            return (
              <Badge 
                key={index} 
                variant="secondary"
                className={cn("text-xs", typeConfig.label !== 'Unknown Event' ? typeConfig.color : 'text-gray-600')}
              >
                {category}
              </Badge>
            );
          })}
          {(detection.categories || []).length === 0 && displayValue(null)}
        </div>
      ),
    },
    // { // clickThroughRate might be less relevant for direct alert display, can be in details
    //   key: "clickThroughRate",
    //   header: "Click-Through Rate",
    //   cell: (detection: PhishingDetection) => (
    //     <span>
    //       {displayValue(detection.clickThroughRate !== null ? `${(detection.clickThroughRate * 100).toFixed(1)}%` : null)}
    //     </span>
    //   ),
    //   sortable: true,
    // },
    {
      key: "detectionSource",
      header: "Source",
      cell: (detection: PhishingDetection) => (
         <Badge variant="outline">{displayValue(detection.detectionSource)}</Badge>
      ),
      sortable: true,
    },
    {
      key: "timestamp",
      header: "Timestamp",
      cell: (detection: PhishingDetection) => (
        <span>{formatAlertTimestamp(detection.timestamp)}</span>
      ),
      sortable: true,
    },
  ];

  return (
    <DataTable columns={columns} data={detections} className={className} />
  );
};

export default PhishingDetectionsTable;
