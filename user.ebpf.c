#define _POSIX_C_SOURCE 200112L
#include <stdio.h>
#include <libelf.h>
#include <fcntl.h>
#include <gelf.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <errno.h>
#include <signal.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include "params.h"

struct bin_freq {
    char *name;
    __u64 count;
};

int compar(const void *a, const void *b) {
    return ((struct bin_freq *)b)->count - ((struct bin_freq *)a)->count;
}

int main(int argc, char **argv) {

    __u16 timeout = DEFAULT_TIMEOUT; // so timeout can hold up to 65535 seconds

    if (argc > 1) {
        if (strcmp(argv[1], "-h") == 0 || strcmp(argv[1], "--help") == 0) {
            printf("Usage: sudo ./user.ebpf <timeout_in_seconds>\n"
                   "Default timeout is 300 seconds(5 mins.)\n");
            return 0;
        }
        char *endptr;
        long timeout_t = strtol(argv[1], &endptr, 10);
        if (errno == ERANGE) {
            printf("Resulting value is out of range"
                   "Setting default timeout: 300 seconds\n" );
        } else if (endptr == argv[1]) {
            printf("Provided timeout contains invalid character(s)"
                   "Setting default timeout: 300 seconds\n");
        } else
            timeout = timeout_t;
    } else {
        printf("If you want to override the default timeout value = 300 seconds run the following: \n"
               "sudo ./user.ebpf <timeout_in_seconds>\n");
    }

    // check the elf version or fail
    if (elf_version(EV_CURRENT) == EV_NONE) {
        fprintf(stderr, "ELF library initialization failed.\n");
        return 1;
    }

    int err = 0;

    // open the backend
    struct bpf_object *obj = bpf_object__open_file("prefetch_hint.ebpf.o", NULL);
    if (!obj) {
        printf("Couldn't load the ebpf kernel object\n");
        return 1;
    }

    // find the program
    struct bpf_program *bpf_prog = bpf_object__find_program_by_name(obj, "watch_hot_bins");
    if (!bpf_prog) {
        printf("Failed to find the program 'watch_hot_bins'\n");
        return 1;
    }

    // load the program
    err = bpf_object__load(obj);
    if (err) {
        printf("Failed to load the program 'watch_hot_bins'\n");
        return 1;
    }

    // attach the program
    struct bpf_link *bpf_l = bpf_program__attach(bpf_prog);
    //struct bpf_link *bpf_l = bpf_program__attach_kprobe(bpf_prog, false, "execve");
    if (!bpf_l) {
        printf("Couldn't attach the program 'watch_hot_bins'\n");
        return 1;
    }

    // find the map
    struct bpf_map *bin_freq_map = bpf_object__find_map_by_name(obj, "bin_freq_map");
    // get the maps's fd
    int map_fd = bpf_map__fd(bin_freq_map);

    // declare an array to hold all frequently executed binaries 
    struct bin_freq bf[MAX_ENTRIES] = {0};

    // The start of the infinity loop. checks new binaries for prefetching
    for (;;) {
        sleep(timeout);
        
        char first_key[MAX_FILENAME_LENGTH] = {0};
        bpf_map_get_next_key(map_fd, NULL, first_key);

        __u64 count;
        // get the first key from the map
        bpf_map_lookup_elem(map_fd, first_key, &count);
        __u16 i = 0;
        __u16 len = strlen(first_key);  
        
        bf[i].name = (char *)malloc(len + 1);
        
        // copy the first entry from the map into the array 
        strncpy(bf[i].name, first_key, len);
        bf[i].name[len] = '\0';   /* put the NULL at the end */
        bf[i].count = count;
        
        char next_key[MAX_FILENAME_LENGTH] = {0};
        char *cur_key = first_key;
        
        // get the rest of the entries from the map
        while (bpf_map_get_next_key(map_fd, cur_key, next_key) == 0) {
            bpf_map_lookup_elem(map_fd, next_key, &count);
            i++;
            len = strlen(next_key);
            bf[i].name = (char *)malloc(len + 1);
            strncpy(bf[i].name, next_key, len);
            bf[i].name[len] = '\0'; 
            bf[i].count = count;
            // assign the address of the current key in the map to the cur_key. 
            // next_key now will be cur_key next iteration
            cur_key = next_key;
        }

        // pick up the most 25 frequently called binaries, this can be changed adjusting the value of the MAX_ENTRIES
        qsort(bf, MAX_ENTRIES, sizeof(struct bin_freq), compar);
        
        int fd;
        Elf_Cmd c = ELF_C_READ;

        int limit;
        #ifdef MAX_NUM_BINS_PRF
            limit = MAX_NUM_BINS_PRF - 1;
        #else
            limit = i;
        #endif
        /* get the offsets and sizes for ".text" sections of hot binaries */
        for (int idx = 0; idx <= limit && bf[idx].name != NULL; idx++) {
            fd = open(bf[idx].name, O_RDONLY);
            if (fd < 0) {
                printf("open() failed for %s\n", bf[idx].name);
                //return 1;
                continue;
            }

            Elf *elf = elf_begin(fd, c, (Elf *)0);
            if (!elf) {
                printf("elf_begin() failed for %s\n", bf[idx].name);
                close(fd);
                continue;
                //return 1;
            }

            size_t sindx;
            if (elf_getshdrstrndx(elf, &sindx) != 0) {
                perror("elf_getshdrstrndx() failed.");
                printf("skipping: %s. ", bf[idx].name);
                printf("something wrong with the 'elf' argument, possibly it's not an elf at all, e.g. which(shell script:))\n");
                // ^there are not specific error codes to check the exact cause, only single generic one [ELF_E_ARGUMENT]
                elf_end(elf);
                close(fd);
                //return 1;
                continue;
            }

            Elf_Scn *scn = NULL;
            while ((scn = elf_nextscn(elf, scn)) != NULL) {
                GElf_Shdr shdr;
                if (!gelf_getshdr(scn, &shdr)) 
                    continue;

                char *name = elf_strptr(elf, sindx, shdr.sh_name);
                if (!name) 
                    continue;

                if (strcmp(name, ".text") == 0) {
                    /* advise the kernel to prefetch ".text" sections of hot binaries */
                    if (posix_fadvise(fd, (unsigned long)shdr.sh_offset, (unsigned long)shdr.sh_size, POSIX_FADV_WILLNEED) == 0)
                        printf("The kernel followed the hint. Prefetching hint for: %s\n", bf[idx].name);
                    break;
                }
            }

            // release an ELF descriptor
            elf_end(elf);
            close(fd);
        }
        printf("here starts the NEXT round\n");
    }

    return 0;
}
