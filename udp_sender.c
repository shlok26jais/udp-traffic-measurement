#define _POSIX_C_SOURCE 200809L
#include <arpa/inet.h>
#include <errno.h>
#include <netdb.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

static uint64_t htonll_u64(uint64_t value) {
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
    return ((uint64_t)htonl((uint32_t)(value & 0xffffffffULL)) << 32) |
           htonl((uint32_t)(value >> 32));
#else
    return value;
#endif
}

static double seconds_between(struct timespec a, struct timespec b) {
    return (double)(b.tv_sec - a.tv_sec) +
           (double)(b.tv_nsec - a.tv_nsec) / 1e9;
}

static int parse_positive_double(const char *s, double *out) {
    char *end = NULL;
    errno = 0;
    double v = strtod(s, &end);
    if (errno || end == s || *end != '\0' || v <= 0.0) return 0;
    *out = v;
    return 1;
}

static int parse_long_range(const char *s, long min, long max, long *out) {
    char *end = NULL;
    errno = 0;
    long v = strtol(s, &end, 10);
    if (errno || end == s || *end != '\0' || v < min || v > max) return 0;
    *out = v;
    return 1;
}

static int sleep_until(const struct timespec *deadline)
{
    struct timespec now, delay;

    while (1) {
        if (clock_gettime(CLOCK_MONOTONIC, &now) == -1)
            return errno;

        delay.tv_sec = deadline->tv_sec - now.tv_sec;
        delay.tv_nsec = deadline->tv_nsec - now.tv_nsec;

        if (delay.tv_nsec < 0) {
            delay.tv_sec--;
            delay.tv_nsec += 1000000000L;
        }

        if (delay.tv_sec < 0 ||
            (delay.tv_sec == 0 && delay.tv_nsec <= 0))
            return 0;

        if (nanosleep(&delay, NULL) == -1 && errno != EINTR)
            return errno;
    }
}

int main(int argc, char **argv) {
    if (argc != 6) {
        fprintf(stderr, "Usage: %s <destination-ip/host> <port> <rate-Mbps> <packet-size-bytes> <duration-seconds>\n", argv[0]);
        fprintf(stderr, "Packet size includes the 8-byte sequence-number header; minimum is 8 bytes.\n");
        return EXIT_FAILURE;
    }

    long port_l, packet_size_l, duration_l;
    double rate_mbps;
    if (!parse_long_range(argv[2], 1, 65535, &port_l) ||
        !parse_positive_double(argv[3], &rate_mbps) ||
        !parse_long_range(argv[4], 8, 65507, &packet_size_l) ||
        !parse_long_range(argv[5], 1, 86400, &duration_l)) {
        fprintf(stderr, "Error: invalid arguments. Port must be 1..65535, rate > 0, packet size 8..65507, duration 1..86400.\n");
        return EXIT_FAILURE;
    }

    struct addrinfo hints, *result = NULL;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_DGRAM;
    int gai = getaddrinfo(argv[1], argv[2], &hints, &result);
    if (gai != 0) {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(gai));
        return EXIT_FAILURE;
    }

    int sock = socket(result->ai_family, result->ai_socktype, result->ai_protocol);
    if (sock < 0) {
        perror("socket");
        freeaddrinfo(result);
        return EXIT_FAILURE;
    }

    unsigned char *packet = calloc((size_t)packet_size_l, 1);
    if (!packet) {
        perror("calloc");
        close(sock);
        freeaddrinfo(result);
        return EXIT_FAILURE;
    }

    const uint64_t packet_size = (uint64_t)packet_size_l;
    const double target_bps = rate_mbps * 1000000.0;
    const double interval = (double)(packet_size * 8ULL) / target_bps;
    if (interval <= 0.0) {
        fprintf(stderr, "Error: calculated packet interval is too small.\n");
        free(packet);
        close(sock);
        freeaddrinfo(result);
        return EXIT_FAILURE;
    }

    printf("UDP sender starting\n");
    printf("Destination: %s:%ld\n", argv[1], port_l);
    printf("Requested application rate: %.3f Mbps\n", rate_mbps);
    printf("Packet size: %ld bytes (includes 8-byte sequence header)\n", packet_size_l);
    printf("Duration: %ld seconds\n", duration_l);
    printf("Target packet interval: %.3f microseconds\n", interval * 1e6);
    fflush(stdout);

    struct timespec start, now, deadline;
    if (clock_gettime(CLOCK_MONOTONIC, &start) != 0) {
        perror("clock_gettime");
        free(packet);
        close(sock);
        freeaddrinfo(result);
        return EXIT_FAILURE;
    }
    uint64_t sent_packets = 0, sent_bytes = 0;
    uint64_t send_errors = 0;
    double duration = (double)duration_l;

    while (1) {
        if (clock_gettime(CLOCK_MONOTONIC, &now) != 0) {
            perror("clock_gettime");
            break;
        }
        double elapsed = seconds_between(start, now);
        if (elapsed >= duration) break;

        uint64_t seq_network = htonll_u64(sent_packets);
        memcpy(packet, &seq_network, sizeof(seq_network));

        ssize_t n = sendto(sock, packet, (size_t)packet_size_l, 0,
                           result->ai_addr, result->ai_addrlen);
        if (n == (ssize_t)packet_size_l) {
            sent_packets++;
            sent_bytes += (uint64_t)n;
        } else {
            send_errors++;
            if (n < 0 && errno != EINTR) perror("sendto");
        }

        double target_offset = (double)sent_packets * interval;
        deadline = start;
        deadline.tv_sec += (time_t)target_offset;
        deadline.tv_nsec += (long)((target_offset - (time_t)target_offset) * 1e9);
        if (deadline.tv_nsec >= 1000000000L) {
            deadline.tv_sec++;
            deadline.tv_nsec -= 1000000000L;
        }
        (void)sleep_until(&deadline);
    }

    if (clock_gettime(CLOCK_MONOTONIC, &now) != 0) {
        perror("clock_gettime");
        memset(&now, 0, sizeof(now));
    }
    double elapsed = seconds_between(start, now);
    if (elapsed <= 0.0) elapsed = duration;
    double actual_mbps = ((double)sent_bytes * 8.0) / elapsed / 1000000.0;

    printf("\nSender results\n");
    printf("Elapsed seconds: %.6f\n", elapsed);
    printf("Packets sent: %llu\n", (unsigned long long)sent_packets);
    printf("Application bytes sent: %llu\n", (unsigned long long)sent_bytes);
    printf("Actual sender rate: %.3f Mbps (application datagram bytes)\n", actual_mbps);
    printf("Send errors: %llu\n", (unsigned long long)send_errors);

    free(packet);
    close(sock);
    freeaddrinfo(result);
    return send_errors == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
