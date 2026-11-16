#pragma once
#include <stddef.h>
#include <stdint.h>

int prepare_packet_tunnel_config(const char *config, const char **output);
int run_network_instance(const char *config);
typedef struct {
    const uint8_t *data;
    size_t length;
} PacketSlice;

typedef int (*PacketReceiver)(const PacketSlice *packets, size_t count, void *context);
int packet_tunnel_open(const char *name, PacketReceiver receiver, void *context, uint64_t *handle);
int packet_tunnel_send(uint64_t handle, const PacketSlice *packets, size_t count);
int packet_tunnel_close(uint64_t handle);
size_t packet_tunnel_batch_capacity(void);
int delete_network_instance(const char *const *names, size_t count);
int call_json_rpc(const char *service, const char *method, const char *domain,
                  const char *payload, const char **response);
void free_string(const char *value);
