# TQSC Kernel Driver

## Prerequisites
- Windows 10/11 SDK and WDK (Windows Driver Kit).
- Visual Studio 2019/2022 with "Desktop development with C++".

## Compilation
1. Open Visual Studio.
2. Create a new "Empty WDM Driver" project.
3. Add `TqscDriver.h`, `TqscDriver.c`, and `TqscDriver.inf` to the project.
4. Build the solution (Release/x64).
5. The output will be `TqscDriver.sys` and `TqscDriver.inf`.

## Deployment
1. Enable Test Signing on the target machine: `bcdedit /set testsigning on` and restart.
2. Right click `TqscDriver.inf` and click Install, or use `sc create`:
   ```cmd
   sc create TqscDriver type= kernel binPath= C:\path\to\TqscDriver.sys
   ```
3. Start the driver:
   ```cmd
   sc start TqscDriver
   ```

## Usage
User-mode Python can communicate via IOCTL `0x800` (Get Events) and `0x801` (Add Block PID).
