# cybersec_1_path_hijacker
a unix programming project to help find risk factor in environment variables 
This is the final touch. A professional **README.md** is what translates your raw C code into a credible "Project" for your GitHub or ECE portfolio. It shows recruiters that you don't just write code—you understand the architecture and the "Why" behind it.

Here is a human-centric, technically precise README for your **PATH Hijack Detector & Sentry**.

---

# PATH Hijack Detector & Sentry (v3.0)

### A Real-Time UNIX System Security Tool

## Project Overview

As an ECE student focusing on Linux internals, I built this tool to address a classic privilege escalation vector: **PATH Hijacking**. This tool operates in two phases: it first performs a static audit of the process environment to find misconfigured directories, and then transitions into an active kernel-level monitor to catch injection attempts in real-time.

---

## How to Build and Run

### 1. Prerequisites

* **OS:** Linux (Requires the `inotify` kernel subsystem).
* **Compiler:** `gcc`
* **Header Files:** `sys/stat.h`, `sys/inotify.h`, `signal.h`.

### 2. Compilation

Use the following command to compile the source code:

```bash
gcc -o path_detector detector.c

```

### 3. Usage

Run the detector as a normal user to audit your current session:

```bash
./path_detector

```

### 4. Testing the Real-Time Sentry

To see the tool catch an attack, create a "vulnerable" directory (world-writable, no sticky bit) and add it to your PATH:

```bash
# Terminal 1: Setup and Run
mkdir ~/vulnerable_dir
chmod 777 ~/vulnerable_dir
export PATH="$HOME/vulnerable_dir:$PATH"
./path_detector

# Terminal 2: Simulate an injection
touch ~/vulnerable_dir/ls

```

*The Sentry in Terminal 1 will immediately log the creation of the malicious `ls` file.*

---

## The "Internalist" Algorithm

This tool follows a structured logic flow that moves from **User Space** configuration to **Kernel Space** enforcement.

### Phase 1: Environment Tokenization (User Space)

* **The Problem:** `strtok()` is "greedy" and skips empty delimiters (`::`), which the shell interprets as the Current Working Directory (CWD).
* **The Solution:** The tool uses **Pointer Arithmetic** (`strchr` and length offsets) to manually parse the `PATH` string, ensuring that leading, trailing, or double colons (hidden CWD risks) are flagged.

### Phase 2: Metadata Auditing (Kernel Interface)

For every directory discovered in the PATH, the tool invokes the `stat()` system call. It performs bitwise checks on the `st_mode` field:

1. **Ownership Check:** Verifies if the directory is owned by `root` (UID 0).
2. **Write Permission Check:** Uses `S_IWOTH` to check if "Others" can write to the folder.
3. **Sticky Bit Mitigation:** Checks for `S_ISVTX`. If set (e.g., in `/tmp`), it lowers the risk because users cannot delete or rename each other's files.

### Phase 3: Active Surveillance (Kernel Events)

If a high-risk directory is identified, the tool initializes the **inotify** subsystem.

* **Watch Registration:** It registers an `IN_CREATE` watch on the vulnerable Inodes.
* **The Event Loop:** The process enters a blocking `read()` state. It consumes 0% CPU until the Kernel detects a file creation in a watched folder and "wakes up" the process to log the alert.

### Phase 4: Graceful Shutdown (Signal Handling)

The tool implements a `SIGINT` (Ctrl+C) handler. This ensures that when the user stops the monitor, the program intercepts the asynchronous signal to provide a final summary of captured security events before closing the file descriptors.

---

## 🛠 Lessons Learned

* **TOCTOU Risks:** Understanding that there is a time gap between "Check" (Audit) and "Use" (Execution) led to the implementation of the real-time Sentry.
* **System Call Efficiency:** Learning how `read()` on an `inotify` descriptor is more efficient than "polling" (looping) the filesystem.
* **Privilege Escalation Logic:** Fully grasped how a SUID binary calling a relative command can be tricked into running attacker-controlled code via PATH manipulation.

---

## 🏁 Final Project Check

* [x] Read and Parse `PATH` safely.
* [x] Bitwise permission checks.
* [x] Real-time injection detection.
* [x] Asynchronous Signal Handling.

---

### What's next for you?

You can now officially add **"Linux Systems Programming & Security Auditing"** to your resume.

**Would you like me to show you how to wrap this whole project into a professional Makefile so you can handle cross-compilation and "clean" builds?** (This is the industry standard for ECE projects).
