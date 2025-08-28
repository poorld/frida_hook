# Frida Scripts Collection

This repository contains a collection of Frida scripts for hooking and analyzing various Android applications.

The project includes a powerful `run.bat` utility that automatically compiles the source scripts and attaches to the target process, simplifying the entire workflow.

## Prerequisites

1.  **Frida Tools**: Ensure Frida and Frida-Compile are installed on your host machine.
    ```bash
    pip install frida-tools
    npm install -g frida-compile
    ```
2.  **Android Device**: A rooted Android device with the corresponding `frida-server` binary running.

## Usage

The `run.bat` script is the recommended way to execute the scripts. It handles the compilation of the source file from `src/entries/` into a bundle in `dist/` and then runs it with Frida.

### Mode 1: Attach to a Running Process

This mode attaches the script to an already running application or system process.

**Syntax:**
```bash
run.bat <script_name> <process_name_or_pid>
```

-   `<script_name>`: The name of the script file in `src/entries` (without the `.js` extension).
-   `<process_name_or_pid>`: The name or Process ID (PID) of the target process.

**Example:**
To attach `system.js` to the `system_server` process:
```bash
run.bat system system_server
```

### Mode 2: Spawn a New Application Process

This mode starts the target application and immediately attaches the script to it. This is useful for hooking logic that runs at application startup.

**Syntax:**
```bash
run.bat -f <script_name> <package_name>
```
-   `-f`: A flag to indicate "spawn" mode.
-   `<script_name>`: The name of the script file in `src/entries` (without the `.js` extension).
-   `<package_name>`: The package name of the application to launch.

**Example:**
To launch `com.hlct.navigation` and attach `hlct_navigation.js`:
```bash
run.bat -f hlct_navigation com.hlct.navigation
```

## Project Structure

-   `run.bat`: The main execution script.
-   `src/entries/`: Contains the raw, human-readable JavaScript source files for hooking.
-   `dist/`: The output directory for compiled script bundles. This is created automatically.
-   `utils/`: Contains shared utility functions and helpers for hooking.
