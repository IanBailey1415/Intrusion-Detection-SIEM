public class SIEMTest {
    public static void main(String[] args) {
        // Create a new SIEM instance
        SIEM siem = new SIEM();

        // Test NIDS
        siem.addEvent("Firewall", "Suspicious Network Traffic", "Unusual packet patterns detected");
        siem.addEvent("Router", "Network Scan", "Port scanning activity observed");
        siem.addEvent("Switch", "Traffic Spike", "Sudden increase in network traffic volume");

        // Test HIDS
        siem.addEvent("Workstation1", "File System Change", "Unauthorized file modification in system directory");
        siem.addEvent("Server2", "Process Behavior", "Abnormal process activity detected");

        // Display the dashboard
        siem.displayDashboard();
    }
}
