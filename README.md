## eBPF Prefetch Hints

⚡ **Speed up frequently used binaries** by hinting the Linux kernel to prefetch them — powered by eBPF.

### 🚀 What It Does

This tool uses an eBPF kernel-side program to track execution frequency of binaries under `/usr/bin`, and a user-space controller that:

- Aggregates call frequency from a BPF map
- Periodically identifies hot binaries
- Suggests prefetching those binaries via system hints

### 🔧 Features

- [x] eBPF‑based tracing of binary execution under **/usr/bin**
- [x] Maintains a frequency map of hot binaries in the kernel
- [x] **User‑defined polling interval**  
  &nbsp;&nbsp;• run `sudo ./prefetch_hint <seconds>`  
  &nbsp;&nbsp;• defaults to **300 s** (5 min) when omitted
- [x] Advises the kernel with `posix_fadvise()` to **prefetch the
       *.text* segment** of each hot ELF binary

### Prerequisites

- Linux kernel with eBPF support
- Clang/LLVM and libbpf-dev
- bpftool
- Root privileges


### 🛠️ Build and Run

```
make all
sudo ./prefetch_hint <time_interval>
```

### 📦 Header provenance
The bundled `vmlinux.h` was generated on Ubuntu 22.04.04 LTS (kernel 6.5.0, BTF enabled)
using `bpftool v7.3.0`. Regenerate with `make headers` if you need an exact match
for a custom kernel.
