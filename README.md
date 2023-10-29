# KM-UM-Communication
In user mode, it allows you to read and write through the kernel. It is actually a classic ioctl driver, but the difference is that it allows you to make changes in the cr0 section. It has been tested up to Windows 21H1. If you want to add 22H2, you have to add it yourself.You can access the offsets from the link. https://ntdiff.github.io


## To Run on Your Computer

#### Method 1
```efiguard
  Unsigned Drivers can be loaded using https://github.com/Mattiwatti/EfiGuard
```

#### Method 2
```testmode
  /Activate test mode and restart your computer
  bcdedit /set testsigning on

  /Create and start the service
  sc create steel type= kernel binpath="C:\...\numerickernel.sys"
  sc start steel
  
  /Stop the service when you are done
  sc stop steel

  /Disable test mode
  bcdedit /set testsigning off


```

  
## Usage/Examples
### Read Memory
```c++
DWORD x = Driver.ReadVirtualMemory<DWORD>(pid, ModuleBase + Pointerone, sizeof(DWORD));
```

### Write Memory
```c++
int a=0;
DWORD writeng = ModuleBase + Pointerone;
Driver.WriteVirtualMemory<DWORD>(pid, writeng, a, sizeof(ULONG));
```

### Write CR0 Memory (Best Part)
```c++
int a=0;
DWORD writeng = ModuleBase + Pointerone;
Driver.WriteReadOnlyCrMemory<DWORD>(pid, writeng, a, sizeof(ULONG));
```

  
## Warning

Do not continuously try to write while using Write CR0 Memory. If you cannot lower the IRQL level, you may get a blue screen.
## License

[GNU](https://choosealicense.com/licenses/gpl-3.0/)

  
