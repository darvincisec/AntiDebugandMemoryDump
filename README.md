# AntiDebugandMemoryDump
Anti-Debug and Anti-Memory Dump for Android

Some known techniques for anti-debug and anti-memory dump have been used in this project. The focus is to use these techniques in a stealthy way without relying on Java APIs.

Following are the techniques used
## Anti-Debug for Java
Presence of JDWP in /proc/self/task/comm and in each of task /proc/self/task/<taskid>/comm is an indication that app is debuggable.

## Anti-Debug for Native
Check for TracerPid != 0 in /proc/self/status and in each of task /proc/self/task/<taskid>/status

## Anti-Memorydump 
Anti-Memory dump is useful to protect the app from memory dumping via frida or [Gameguardian](https://gameguardian.net/forum/gallery/image/248-how-to-dump-memory-of-any-running-processes-in-android-gameguardian/) or any other means.
inotify watch of the following files
 1. /proc/self/maps
 2. /proc/self/mem
 3. /proc/self/pagemap 
 4. /proc/self/task/<taskid>/mem
 5. /proc/self/task/<taskid>/pagemap
 
Any attempts to access or open these files is an indication of access to the memory. If you use the techniques in [DetectFrida](https://github.com/darvincisec/DetectFrida), inotify will be triggered. There is no way to filter if the access is by the same process or a different process. fanotify addresses the problem wherein it provides the pid of the process accessing the file. But it is not a valid syscall that can be used by apps

