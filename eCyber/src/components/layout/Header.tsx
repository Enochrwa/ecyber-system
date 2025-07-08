
import React, { useState, useEffect } from 'react';
import { Bell, Search, User, Settings, LogOut } from 'lucide-react';
import io from 'socket.io-client';
import axios from 'axios'; // For fetching initial notifications
import { 
  DropdownMenu, 
  DropdownMenuContent, 
  DropdownMenuItem, 
  DropdownMenuLabel, 
  DropdownMenuSeparator, 
  DropdownMenuTrigger 
} from "@/components/ui/dropdown-menu";
import { Avatar, AvatarFallback, AvatarImage } from "@/components/ui/avatar";
import { ThemeToggle } from "@/components/ui/theme-toggle";
import { Input } from "@/components/ui/input";
import { cn } from '@/lib/utils';
import { Link } from 'react-router-dom';

import usePacketSnifferSocket from '@/hooks/usePacketSnifferSocket';

interface NotificationType {
  id: number | string;
  name: string;
  description: string;
  severity: string;
  timestamp: string; // ISO string
  type: string;
  read: boolean;
}

const MAX_NOTIFICATIONS = 5;

const Header = () => {
  const [isSearchActive, setIsSearchActive] = useState(false);
  const [notifications, setNotifications] = useState<NotificationType[]>([]);

    const { socket } = usePacketSnifferSocket();


  // Set up Socket.IO client
  useEffect(() => {
    // Handler for real-time socket alerts
    if (socket) {
      const handleNewAlert = (newAlert: any) => {
        console.log('Received new_alert:', newAlert);
        const formattedAlert: NotificationType = {
          id: newAlert.id || `socket-alert-${Date.now()}`, // Ensure ID exists
          name: newAlert.name || 'System Alert',
          description: newAlert.description || 'A new alert has been triggered.',
          severity: newAlert.severity || 'info',
          timestamp: newAlert.timestamp || new Date().toISOString(),
          type: newAlert.type || 'socket',
          read: false,
        };
        setNotifications(prevNotifications =>
          [formattedAlert, ...prevNotifications].slice(0, MAX_NOTIFICATIONS)
        );
      };

      socket.on('new_alert', handleNewAlert);
      socket.on('disconnect', (reason) => console.log('Socket.IO disconnected:', reason));
      socket.on('connect_error', (error) => console.error('Socket.IO connection error:', error));

      // Cleanup socket listeners
      return () => {
        socket.off('new_alert', handleNewAlert);
        // socket.disconnect(); // Potentially disconnect elsewhere if socket is shared
      };
    }
  }, [socket]);

  // Listener for custom event for ML predictions
  useEffect(() => {
    const handleMlPredictionEvent = (event: Event) => {
      const customEvent = event as CustomEvent<NotificationType[]>;
      const newMlNotifications = customEvent.detail;

      if (newMlNotifications && newMlNotifications.length > 0) {
        setNotifications(prevNotifications =>
          [...newMlNotifications, ...prevNotifications].slice(0, MAX_NOTIFICATIONS * 2) // Allow more notifs temporarily if many ML come at once
            .sort((a,b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime()) // Re-sort by time
            .slice(0, MAX_NOTIFICATIONS) // Then trim to max
        );
      }
    };

    window.addEventListener('mlPredictionNotification', handleMlPredictionEvent);

    return () => {
      window.removeEventListener('mlPredictionNotification', handleMlPredictionEvent);
    };
  }, []);

  const handleMarkAllAsRead = () => {
    setNotifications(prev => prev.map(n => ({ ...n, read: true })));
  };

  const handleNotificationClick = (id: number | string) => {
    setNotifications(prev => prev.map(n => n.id === id ? { ...n, read: true } : n));
    // Potentially navigate to a detailed view for this notification
  };
  
  return (
    <header className="h-16 bg-background/50 backdrop-blur-lg border-b border-border flex items-center justify-between px-6 z-10">
      {/* Left side - Search */}
      <div className={cn(
        "relative transition-all duration-300",
        isSearchActive ? "w-full md:w-2/3" : "w-64"
      )}>
        <Input
          placeholder="Search threats, logs, IPs..."
          className="pl-10 bg-secondary/50 border-secondary hover:border-isimbi-purple/50 focus:border-isimbi-purple"
          onFocus={() => setIsSearchActive(true)}
          onBlur={() => setIsSearchActive(false)}
        />
        <Search size={18} className="absolute left-3 top-1/2 -translate-y-1/2 text-muted-foreground" />
      </div>
      
      {/* Right side - Actions */}
      <div className="flex items-center space-x-4">
        {/* System status */}
        
        
        {/* Notifications */}
        <DropdownMenu>
          <DropdownMenuTrigger asChild>
            <button className="relative p-2 rounded-full hover:bg-secondary/80 transition-colors">
              <Bell size={20} />
              {notifications.some(n => !n.read) && 
                <span className="absolute top-1 right-1 w-2 h-2 bg-isimbi-purple rounded-full animate-pulse"></span>
              }
            </button>
          </DropdownMenuTrigger>
          <DropdownMenuContent align="end" className="w-96 max-h-96 overflow-y-auto"> {/* Added max-h-96 overflow-y-auto */}
            <DropdownMenuLabel className="flex items-center justify-between">
              <span>Notifications ({notifications.filter(n => !n.read).length} unread)</span>
              {notifications.some(n => !n.read) && (
                <button 
                  onClick={handleMarkAllAsRead} 
                  className="text-xs text-isimbi-purple hover:underline focus:outline-none"
                >
                  Mark all as read
                </button>
              )}
            </DropdownMenuLabel>
            <DropdownMenuSeparator />
            {notifications.length === 0 ? (
              <DropdownMenuItem className="text-muted-foreground text-center p-4">
                No new notifications
              </DropdownMenuItem>
            ) : (
              notifications.map((notification) => (
                <DropdownMenuItem 
                  key={notification.id} 
                  className={`flex flex-col items-start p-3 cursor-pointer hover:bg-secondary/50 ${!notification.read ? 'bg-secondary/30' : ''}`}
                  onClick={() => handleNotificationClick(notification.id)}
                >
                  <div className="flex items-start justify-between w-full">
                    <div className={`font-medium ${!notification.read ? 'text-foreground' : 'text-muted-foreground'}`}>
                      {notification.name}
                    </div>
                    <div className="text-xs text-muted-foreground whitespace-nowrap pl-2">
                      {new Date(notification.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
                    </div>
                  </div>
                  <div className={`text-sm mt-1 ${!notification.read ? 'text-muted-foreground' : 'text-muted-foreground/70'}`}>
                    {notification.description.length > 100 ? notification.description.substring(0, 97) + "..." : notification.description}
                  </div>
                  <div className="flex items-center justify-between w-full mt-1.5">
                    <span className={`text-xs px-1.5 py-0.5 rounded-full ${
                      notification.severity === 'critical' ? 'bg-red-500/20 text-red-500' :
                      notification.severity === 'high' ? 'bg-orange-500/20 text-orange-500' :
                      notification.severity === 'medium' ? 'bg-yellow-500/20 text-yellow-500' :
                      'bg-blue-500/20 text-blue-500' // low or unknown
                    }`}>
                      {notification.severity}
                    </span>
                    {!notification.read && <div className="w-1.5 h-1.5 bg-isimbi-purple rounded-full"></div>}
                  </div>
                </DropdownMenuItem>
              ))
            )}
            <DropdownMenuSeparator />
            <DropdownMenuItem className="text-center text-sm text-muted-foreground hover:text-foreground cursor-pointer">
              View all notifications {/* This would navigate to a dedicated notifications page */}
            </DropdownMenuItem>
          </DropdownMenuContent>
        </DropdownMenu>
        <div>
          <ThemeToggle/>
        </div>
        {/* User menu */}
        <DropdownMenu>
          <DropdownMenuTrigger asChild>
            <button className="flex items-center space-x-2">
              <Avatar className="h-8 w-8 border border-border">
                <AvatarImage src="https://github.com/shadcn.png" />
                <AvatarFallback>JD</AvatarFallback>
              </Avatar>
            </button>
          </DropdownMenuTrigger>
          <DropdownMenuContent align="end">
            <DropdownMenuLabel>My Account</DropdownMenuLabel>
            <DropdownMenuSeparator />
            <DropdownMenuItem className="cursor-pointer">
              <User className="mr-2" size={16} />
              <span>Profile</span>
            </DropdownMenuItem>
            <DropdownMenuItem className="cursor-pointer">
              <Settings className="mr-2" size={16} />
              <span>Settings</span>
            </DropdownMenuItem>
            <DropdownMenuSeparator />
            <DropdownMenuItem className="cursor-pointer text-destructive">
              <LogOut className="mr-2" size={16} />
              <Link to={"/"}>
              <span>Log out</span>
              </Link>
            </DropdownMenuItem>
          </DropdownMenuContent>
        </DropdownMenu>
      </div>
    </header>
  );
};

export default Header;
