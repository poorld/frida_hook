# Frida 脚本集合

本仓库包含一系列用于 Hook 和分析各种 Android 应用的 Frida 脚本。

项目内置了一个功能强大的 `run.bat` 脚本，它可以自动编译源脚本并附加到目标进程，极大地简化了整个工作流程。

## 先决条件

1.  **Frida 工具**: 确保你的电脑上已经安装了 Frida 和 Frida-Compile。
    ```bash
    pip install frida-tools
    npm install -g frida-compile
    ```
2.  **Android 设备**: 一台已经 Root 并运行了对应版本 `frida-server` 的 Android 设备。

## 使用方法

推荐使用 `run.bat` 脚本来执行 Hook。它会自动处理 `src/entries/` 目录下的源文件，将其编译打包到 `dist/` 目录，然后通过 Frida 运行。

### 模式一：附加到正在运行的进程

此模式用于将脚本附加到一个已经在运行的应用或系统进程上。

**语法:**
```bash
run.bat <脚本名> <进程名或PID>
```

-   `<脚本名>`: `src/entries` 目录下脚本的文件名（不需要 `.js` 后缀）。
-   `<进程名或PID>`: 目标进程的名称或进程ID（PID）。

**示例:**
将 `system.js` 附加到 `system_server` 进程：
```bash
run.bat system system_server
```

### 模式二：启动并注入进程

此模式会先启动目标应用，然后立即附加脚本。这对于需要 Hook 应用启动阶段逻辑的场景非常有用。

**语法:**
```bash
run.bat -f <脚本名> <包名>
```
-   `-f`: 固定参数，用于指定“启动”模式。
-   `<脚本名>`: `src/entries` 目录下脚本的文件名（不需要 `.js` 后缀）。
-   `<包名>`: 需要启动的应用的包名。

**示例:**
启动 `com.hlct.navigation` 应用并附加 `hlct_navigation.js` 脚本：
```bash
run.bat -f hlct_navigation com.hlct.navigation
```

## 项目结构

-   `run.bat`: 核心执行脚本。
-   `src/entries/`: 存放可读性高的 Hook 源码（JavaScript 文件）。
-   `dist/`: 存放编译后脚本的输出目录，由 `run.bat` 自动创建。
-   `utils/`: 存放可重用的公共 Hook 工具函数。
