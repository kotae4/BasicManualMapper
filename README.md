# BasicManualMapper #
Barebones usermode module loader inspired by DarthTon's [Blackbone](https://github.com/DarthTon/Blackbone).  

I don't include nearly as much functionality as that library, hence 'barebones'.  
* TLS entries aren't processed at all.  
* Delayed imports aren't processed.  
* Activation contexts aren't used. Manifest files aren't checked.  
* .NET images probably won't work.  
* Exception handling isn't set up. If the module being mapped uses exceptions it will likely crash.  
* WoW64 probably isn't *fully* accounted for (but I did test it on a 32-bit process w/ 32-bit module).  
* Probably some other stuff is missing or broken.  

The things it does do:
* Processes .reloc section, applying relocation fixups.  
* Recursively maps dependent modules without using LoadLibrary at all - even dependencies are manually mapped.  
* Fills in each module's ImportAddressTable.  
* Invokes each module's DllMain using CreateRemoteThread.  
* Has some considerations for WoW64 (mostly just path resolution).

## HOW TO USE ##
1. Build solution
2. Open command prompt as administrator
3. Navigate to folder containing BasicManualMapper.exe
4. Invoke: `BasicManualMapper.exe -dll <Path\\To\\Your\\DLL> -target <ProcessName.exe>`
5. Hope. (please submit bug reports via github issues)