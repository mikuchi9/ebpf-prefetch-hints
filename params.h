
// for both userspace and kernelspace
#define MAX_ENTRIES             100         // maximum entries - unique bins in the map
#define MAX_FILENAME_LENGTH     128         // maximum filenale length of an executable (basename, not a full path)

// for kernelspace only
#define MAX_VALUE               500         // max. value each entry can holds (called 500 times and it's going to reset to 0)
#define BIN_PATH_LENGTH         9           // length of '/usr/bin/' = 9
#define BIN_PATH                "/usr/bin/" // look for binaries that exectued at this path

// for userspace only
#define MAX_NUM_BINS_PRF        4           // let advise the kernel to prefetch only the specified numeber of the frequently executed bins
#define DEFAULT_TIMEOUT         (5 * 60)    // 5 minutes in seconds // polling frequency of the bins' frequency map