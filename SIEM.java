import java.util.*;
import java.time.LocalDateTime;

public class SIEM {
    private List<SecurityEvent> events;
    private Map<String, Integer> threatCount;
    private List<IDS> idsSystems;
    
    public SIEM() {
        events = new ArrayList<>();
        threatCount = new HashMap<>();
        idsSystems = new ArrayList<>();
        // Initialize with default IDS systems
        idsSystems.add(new NIDS());
        idsSystems.add(new HIDS());
    }
    
    public void addEvent(String source, String eventType, String description) {
        SecurityEvent event = new SecurityEvent(source, eventType, description);
        events.add(event);
        analyzeThreat(event);
        // Process event through all IDS systems
        for (IDS ids : idsSystems) {
            ids.analyzeEvent(event);
        }
    }
    
    private void analyzeThreat(SecurityEvent event) {
        // Simple threat analysis based on event type
        if (event.getEventType().toLowerCase().contains("attack") ||
            event.getEventType().toLowerCase().contains("breach") ||
            event.getEventType().toLowerCase().contains("malware")) {
            
            threatCount.put(event.getEventType(), threatCount.getOrDefault(event.getEventType(), 0) + 1);
            
            if (threatCount.get(event.getEventType()) >= 5) {
                triggerAlert(event);
            }
        }
    }
    
    private void triggerAlert(SecurityEvent event) {
        System.out.println("ALERT: Potential security threat detected!");
        System.out.println("Event Type: " + event.getEventType());
        System.out.println("Source: " + event.getSource());
        System.out.println("Description: " + event.getDescription());
        System.out.println("Timestamp: " + event.getTimestamp());
    }
    
    public void displayDashboard() {
        System.out.println("SIEM Dashboard");
        System.out.println("Total Events: " + events.size());
        System.out.println("Threat Summary:");
        for (Map.Entry<String, Integer> entry : threatCount.entrySet()) {
            System.out.println("- " + entry.getKey() + ": " + entry.getValue());
        }
        System.out.println("\nIDS Reports:");
        for (IDS ids : idsSystems) {
            ids.displayReport();
        }
    }
    
    private static class SecurityEvent {
        private String source;
        private String eventType;
        private String description;
        private LocalDateTime timestamp;
        
        public SecurityEvent(String source, String eventType, String description) {
            this.source = source;
            this.eventType = eventType;
            this.description = description;
            this.timestamp = LocalDateTime.now();
        }
        
        // Getters
        public String getSource() { return source; }
        public String getEventType() { return eventType; }
        public String getDescription() { return description; }
        public LocalDateTime getTimestamp() { return timestamp; }
    }
    
    // New IDS interface
    private interface IDS {
        void analyzeEvent(SecurityEvent event);
        void displayReport();
    }

    // Network-based IDS implementation
    private class NIDS implements IDS {
        private int suspiciousNetworkActivities = 0;

        @Override
        public void analyzeEvent(SecurityEvent event) {
            if (event.getEventType().toLowerCase().contains("network") ||
                event.getDescription().toLowerCase().contains("traffic") ||
                event.getDescription().toLowerCase().contains("packet")) {
                suspiciousNetworkActivities++;
                if (suspiciousNetworkActivities % 3 == 0) { // Alert every 3 suspicious activities
                    System.out.println("NIDS ALERT: Suspicious network activity detected!");
                    System.out.println("Event: " + event.getEventType());
                    System.out.println("Description: " + event.getDescription());
                }
            }
        }

        @Override
        public void displayReport() {
            System.out.println("NIDS Report:");
            System.out.println("- Suspicious Network Activities: " + suspiciousNetworkActivities);
        }
    }

    // Host-based IDS implementation
    private class HIDS implements IDS {
        private int unauthorizedFileModifications = 0;
        private int abnormalProcessBehaviors = 0;

        @Override
        public void analyzeEvent(SecurityEvent event) {
            if (event.getDescription().toLowerCase().contains("file modification")) {
                unauthorizedFileModifications++;
                System.out.println("HIDS ALERT: Unauthorized file modification detected!");
                System.out.println("Event: " + event.getEventType());
                System.out.println("Description: " + event.getDescription());
            } else if (event.getDescription().toLowerCase().contains("process") &&
                       event.getDescription().toLowerCase().contains("abnormal")) {
                abnormalProcessBehaviors++;
                System.out.println("HIDS ALERT: Abnormal process behavior detected!");
                System.out.println("Event: " + event.getEventType());
                System.out.println("Description: " + event.getDescription());
            }
        }

        @Override
        public void displayReport() {
            System.out.println("HIDS Report:");
            System.out.println("- Unauthorized File Modifications: " + unauthorizedFileModifications);
            System.out.println("- Abnormal Process Behaviors: " + abnormalProcessBehaviors);
        }
    }
}
