### DLLFinder

DLLFinder is a powerful and efficient C tool designed to provide developers and security professionals with the ability to enumerate all the Dynamic Link Libraries (DLLs) loaded by a specified process on the Windows operating system.

### Features

- [x] DLLs Enumeration
- [x] MockingJay Support

### Commands

- Enumerating Dlls
```
dllfinder.exe --process_name "notepad.exe" 
```
- MockingJay
```
dllfinder.exe  --mockingjay --PEfilePath "file_path" 
```
### Windows API Used
- FindTargetProc
- OpenProcess
- CreateToolhelp32Snapshot
- Process32First
- Process32Next
- EnumProcessModulesEx
- GetModuleFileNameExA

### Working POC

![POC](https://github.com/SecTheBit/DLLFinder/assets/46895441/b11b35d3-eeaf-4559-a1f0-4053f7ce52fa)
![dllfinder](https://github.com/SecTheBit/DLLFinder/assets/46895441/ce61c106-ac86-4aeb-be23-d31ee468f354)


### Refrences
- https://github.com/0xRick/PE-Parser
- https://www.securityjoes.com/post/process-mockingjay-echoing-rwx-in-userland-to-achieve-code-execution
