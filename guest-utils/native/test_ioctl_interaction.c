#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <errno.h>
#include <linux/sockios.h>

typedef struct rt3052_esw_reg {
	unsigned int off;
	unsigned int val;
} esw_reg;

// Helper function to parse IOCTL command arguments
unsigned int parse_ioctl_cmd(const char *cmd_str) {
    // Check for common IOCTL commands by name
    if (strcasecmp(cmd_str, "SIOCGIFFLAGS") == 0) return SIOCGIFFLAGS;
    if (strcasecmp(cmd_str, "SIOCGIFADDR") == 0) return SIOCGIFADDR;
    if (strcasecmp(cmd_str, "SIOCSIFFLAGS") == 0) return SIOCSIFFLAGS;
    if (strcasecmp(cmd_str, "SIOCGIFINDEX") == 0) return SIOCGIFINDEX;
    if (strcasecmp(cmd_str, "SIOCGIFHWADDR") == 0) return SIOCGIFHWADDR;

    // Try to parse as hexadecimal
    unsigned int cmd = 0;
    if (sscanf(cmd_str, "0x%x", &cmd) == 1 || sscanf(cmd_str, "%x", &cmd) == 1) {
        return cmd;
    }
    
    // Try to parse as decimal
    if (sscanf(cmd_str, "%u", &cmd) == 1) {
        return cmd;
    }
    
    fprintf(stderr, "Error: Unknown IOCTL command '%s'\n", cmd_str);
    exit(EXIT_FAILURE);
}

int main(int argc, char *argv[]) {
    int sockfd;
    struct ifreq ifr;
    int data = 0;
    char *interface = "eth0";  // Default network interface
    unsigned int ioctl_cmd;
    unsigned int offset = -1; // Sentinel value to indicate offset mode is not used
    esw_reg esw_data;

    // Check if enough arguments are provided
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <ioctl_command> [interface] [data | --offset <offset_value>]\n", argv[0]);
        fprintf(stderr, "  ioctl_command: SIOCGIFFLAGS, SIOCGIFADDR, etc. or hex value like 0x8915\n");
        fprintf(stderr, "  interface: Network interface (default: eth0)\n");
        fprintf(stderr, "  data: Integer data to pass with ioctl (default: 0)\n");
        fprintf(stderr, "  --offset <offset_value>: Use esw_reg struct with specified offset\n");
        return EXIT_FAILURE;
    }

    // Parse IOCTL command
    ioctl_cmd = parse_ioctl_cmd(argv[1]);
    
    // Parse optional interface name and data/offset
    int arg_idx = 2;
    if (argc > arg_idx && argv[arg_idx][0] != '-') {
        interface = argv[arg_idx];
        arg_idx++;
    }

    if (argc > arg_idx) {
        if (strcmp(argv[arg_idx], "--offset") == 0) {
            if (argc > arg_idx + 1) {
                if (sscanf(argv[arg_idx + 1], "0x%x", &offset) != 1 && sscanf(argv[arg_idx + 1], "%u", &offset) != 1) {
                     fprintf(stderr, "Error: Invalid offset value '%s'\n", argv[arg_idx + 1]);
                     return EXIT_FAILURE;
                }
                // Offset mode is active
            } else {
                fprintf(stderr, "Error: --offset requires a value\n");
                return EXIT_FAILURE;
            }
        } else {
            // Assume it's integer data
            data = atoi(argv[arg_idx]);
        }
    }

    // Create a socket (doesn't matter which type for ioctl)
    if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        perror("Failed to create socket");
        return EXIT_FAILURE;
    }

    // Set up the interface request struct
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, interface, IFNAMSIZ-1);
    
    // Set the data pointer based on mode
    if (offset != -1) {
        // Offset mode: use esw_reg struct
        memset(&esw_data, 0, sizeof(esw_data));
        esw_data.off = offset;
        ifr.ifr_data = (void *)&esw_data;
        printf("Sending ioctl command 0x%x to interface %s using esw_reg with offset: 0x%x\n", 
               ioctl_cmd, interface, offset);
    } else {
        // Data mode: use integer data
        ifr.ifr_data = (void *)&data;
        printf("Sending ioctl command 0x%x to interface %s with data: %d\n", 
               ioctl_cmd, interface, data);
    }

    int ret = ioctl(sockfd, ioctl_cmd, &ifr);

    // Attempt to send the ioctl command
    if (ret < 0) {
        perror("IOCTL command failed");
        close(sockfd);
        return EXIT_FAILURE;
    }

    printf("IOCTL command sent successfully! returned %x\n", ret);
    
    // Display results
    if (offset != -1) {
        // Offset mode: print returned value
        printf("Returned esw_reg value (val): 0x%x (%u)\n", esw_data.val, esw_data.val);
    } else {
        // Data mode: display results for common query operations
        if (ioctl_cmd == SIOCGIFFLAGS) {
            printf("Interface flags: 0x%x\n", ifr.ifr_flags);
        } else if (ioctl_cmd == SIOCGIFINDEX) {
            printf("Interface index: %d\n", ifr.ifr_ifindex);
        }
        // Potentially print the integer data if it was modified (depends on ioctl)
        // printf("Returned data value: %d\n", data); 
    }
    
    // Clean up
    close(sockfd);
    return EXIT_SUCCESS;
}