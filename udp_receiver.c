#define _POSIX_C_SOURCE 200809L
#include <arpa/inet.h>
#include <errno.h>
#include <inttypes.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#define MAX_DATAGRAM 65507
#define INITIAL_SEEN_CAPACITY 1024

typedef struct {
    uint64_t packets;
    uint64_t bytes;
} Bucket;

static uint64_t ntohll_u64(uint64_t value) {
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
    return ((uint64_t)ntohl((uint32_t)(value & 0xffffffffULL)) << 32) |
           ntohl((uint32_t)(value >> 32));
#else
    return value;
#endif
}

static double seconds_between(struct timespec a, struct timespec b) {
    return (double)(b.tv_sec - a.tv_sec) +
           (double)(b.tv_nsec - a.tv_nsec) / 1e9;
}

static int parse_long_range(const char *s, long min, long max, long *out) {
    char *end = NULL;
    errno = 0;
    long v = strtol(s, &end, 10);
    if (errno || end == s || *end != '\0' || v < min || v > max) return 0;
    *out = v;
    return 1;
}

static int ensure_seen(unsigned char **seen, size_t *capacity, uint64_t seq) {
    if (seq > 100000000ULL) return 0; /* Guard against malformed/unbounded sequence values. */
    size_t needed = (size_t)seq + 1;
    if (needed > *capacity) {
        size_t newcap = *capacity;
        while (newcap < needed) {
            if (newcap > 50000000U) return 0;
            newcap *= 2;
        }
        unsigned char *tmp = realloc(*seen, newcap);
        if (!tmp) return 0;
        memset(tmp + *capacity, 0, newcap - *capacity);
        *seen = tmp;
        *capacity = newcap;
    }
    return 1;
}

int main(int argc, char **argv) {
    if (argc < 3 || argc > 4) {
        fprintf(stderr, "Usage: %s <port> <duration-seconds> [csv-output]\n", argv[0]);
        fprintf(stderr, "Receiver listens for the duration plus a 2-second drain window.\n");
        return EXIT_FAILURE;
    }

    long port_l, duration_l;
    if (!parse_long_range(argv[1], 1, 65535, &port_l) ||
        !parse_long_range(argv[2], 1, 86400, &duration_l)) {
        fprintf(stderr, "Error: port must be 1..65535 and duration must be 1..86400 seconds.\n");
        return EXIT_FAILURE;
    }
    const char *csv_path = argc == 4 ? argv[3] : "receiver_stats.csv";

    FILE *csv = fopen(csv_path, "w");
    if (!csv) {
        perror("fopen CSV");
        return EXIT_FAILURE;
    }
    fprintf(csv, "second,packets_received,bytes_received,application_mbps\n");

    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        perror("socket");
        fclose(csv);
        return EXIT_FAILURE;
    }

    int reuse = 1;
    (void)setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons((uint16_t)port_l);
    if (bind(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("bind");
        close(sock);
        fclose(csv);
        return EXIT_FAILURE;
    }

    struct timeval timeout = { .tv_sec = 0, .tv_usec = 100000 };
    if (setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) < 0) {
        perror("setsockopt SO_RCVTIMEO");
        close(sock);
        fclose(csv);
        return EXIT_FAILURE;
    }

    unsigned char *buffer = malloc(MAX_DATAGRAM);
    unsigned char *seen = calloc(INITIAL_SEEN_CAPACITY, 1);
    size_t seen_capacity = INITIAL_SEEN_CAPACITY;
    Bucket *buckets = calloc((size_t)duration_l + 3, sizeof(Bucket));
    if (!buffer || !seen || !buckets) {
        perror("allocation");
        free(buffer);
        free(seen);
        free(buckets);
        close(sock);
        fclose(csv);
        return EXIT_FAILURE;
    }

    printf("UDP receiver listening on port %ld\n", port_l);
    printf("Measurement duration: %ld seconds plus 2-second drain window\n", duration_l);
    printf("Per-second CSV: %s\n", csv_path);
    fflush(stdout);

    struct timespec start, now;
    if (clock_gettime(CLOCK_MONOTONIC, &start) != 0) {
        perror("clock_gettime");
        free(buffer); free(seen); free(buckets);
        close(sock); fclose(csv);
        return EXIT_FAILURE;
    }

    uint64_t total_packets = 0, total_bytes = 0, unique_packets = 0;
    uint64_t duplicates = 0, malformed = 0, max_seq = 0;
    int have_seq = 0;
    double total_window = (double)duration_l + 2.0;

    for (;;) {
        if (clock_gettime(CLOCK_MONOTONIC, &now) != 0) {
            perror("clock_gettime");
            break;
        }
        double elapsed = seconds_between(start, now);
        if (elapsed >= total_window) break;

        struct sockaddr_storage peer;
        socklen_t peer_len = sizeof(peer);
        ssize_t n = recvfrom(sock, buffer, MAX_DATAGRAM, 0,
                             (struct sockaddr *)&peer, &peer_len);
        if (n < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) continue;
            perror("recvfrom");
            break;
        }
        if (n < (ssize_t)sizeof(uint64_t)) {
            malformed++;
            continue;
        }

        uint64_t seq_network;
        memcpy(&seq_network, buffer, sizeof(seq_network));
        uint64_t seq = ntohll_u64(seq_network);
        if (!ensure_seen(&seen, &seen_capacity, seq)) {
            malformed++;
            continue;
        }

        if (seen[seq]) {
            duplicates++;
        } else {
            seen[seq] = 1;
            unique_packets++;
        }
        if (!have_seq || seq > max_seq) max_seq = seq;
        have_seq = 1;

        total_packets++;
        total_bytes += (uint64_t)n;
        if (elapsed < 0) elapsed = 0;
        size_t bucket_index = (size_t)elapsed;
        size_t max_bucket = (size_t)duration_l + 2;
        if (bucket_index > max_bucket) bucket_index = max_bucket;
        buckets[bucket_index].packets++;
        buckets[bucket_index].bytes += (uint64_t)n;
    }

    for (long sec = 0; sec < duration_l + 2; sec++) {
        double mbps = (double)buckets[sec].bytes * 8.0 / 1000000.0;
        printf("Second %ld: packets=%" PRIu64 ", bytes=%" PRIu64 ", payload-datagram rate=%.6f Mbps\n",
               sec + 1, buckets[sec].packets, buckets[sec].bytes, mbps);
        fprintf(csv, "%ld,%" PRIu64 ",%" PRIu64 ",%.6f\n",
                sec + 1, buckets[sec].packets, buckets[sec].bytes, mbps);
    }

    uint64_t estimated_lost = 0;
    if (have_seq && max_seq < 100000000ULL) {
        uint64_t expected = max_seq + 1; /* Sender sequence starts at zero. */
        if (expected > unique_packets) estimated_lost = expected - unique_packets;
    }
    double loss_pct = (have_seq && max_seq + 1 > 0)
        ? (double)estimated_lost * 100.0 / (double)(max_seq + 1) : 0.0;
    double received_mbps = (double)total_bytes * 8.0 / ((double)duration_l * 1000000.0);

    printf("\nReceiver summary\n");
    printf("Datagrams received (including duplicates): %" PRIu64 "\n", total_packets);
    printf("Unique sequence numbers received: %" PRIu64 "\n", unique_packets);
    printf("Application bytes received: %" PRIu64 "\n", total_bytes);
    printf("Received rate over configured duration: %.3f Mbps\n", received_mbps);
    printf("Highest sequence number observed: ");
    if (have_seq) printf("%" PRIu64 "\n", max_seq);
    else printf("none\n");
    printf("Estimated missing sequence numbers: %" PRIu64 "\n", estimated_lost);
    printf("Estimated loss percentage: %.3f%%\n", loss_pct);
    printf("Duplicates: %" PRIu64 "\n", duplicates);
    printf("Malformed/ignored packets: %" PRIu64 "\n", malformed);

    fclose(csv);
    free(buffer);
    free(seen);
    free(buckets);
    close(sock);
    printf("Receiver stopped; CSV saved to %s\n", csv_path);
    return EXIT_SUCCESS;
}
