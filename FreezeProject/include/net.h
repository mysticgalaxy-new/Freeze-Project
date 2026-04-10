#ifndef NET_H
#define NET_H

#include <stdint.h>

struct net_device {
    const char *name;
    void (*init)(void);
    int  (*link_up)(void);
    void (*poll)(void);
};

extern struct net_device *active_net;
void net_scan_pci(void);
void net_poll(void);
int net_ready(void);
int net_import_http(const char *url,
                    const char *forced_name,
                    char *out_name,
                    uint32_t out_name_cap,
                    char *out_data,
                    uint32_t out_cap,
                    uint32_t *out_len);

int net_import_tftp(const char *url,
                    const char *forced_name,
                    char *out_name,
                    uint32_t out_name_cap,
                    char *out_data,
                    uint32_t out_cap,
                    uint32_t *out_len);

#endif
