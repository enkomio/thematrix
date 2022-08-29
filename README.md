# TheMatrix
This project was created to ease the malware analysis process. The goal is to create an activator binary whose purpose is to load a user defined binary and monitor the execution by using Win32 API hooks. Relevant data is then saved to disk. The code supports both x86 and x64 binaries.

# Doc
I wrote a blog post explaining how it works: <a href="http://antonioparata.blogspot.com/2022/06/thematrix-process-inspection-tool-aimed.html">http://antonioparata.blogspot.com/2022/06/thematrix-process-inspection-tool-aimed.html</a>

# Usage
To monitor a new binary is necessary to create an **activator**. The activator will load and monitor a user input binary. To create an activator use the **-add** option. An example of usage is the following one:

```
TheMatrix.exe -add c:\path\to\my\binary.dll
```

This command will create a new PE file representing the activator. The activator will have the same format (DLL or EXE) of the input binary.

Once created, you can just run it in you preferred way (for DLL the suggested way is to use the *rundll32.exe* utility).

During the execution the data generated by the monitored functions is saved to **./Desktop/thematrix/[process ID]/** (this depends on the **log_data** function  implemented in **utility.c**). 

**Limitation**: 
* The project modifies the _PEB.Ldr_ structure in order to allow specific APIs to work correctly (such as _GetModuleHandle_, ...). If you run the activator on a WOW64 system (x86 binary on a x64 OS), only the x86 _PEB.Ldr_ is modified (WOW64 processes have both x86 and x64 PEB). When the CPU changes to x64, the Windows Native APIs (ntdll.dll) will uses the x64 version of _PEB.Ldr_. This implies that the activator might not work properly. To be sure that the x86 works, run the binary on an x86 OS (which are no more maintained :\).

* The newly created file does not export all the methods and does not contain the original file resources. This will cause possible errors, for example if a DLL calls _GetModuleFileName_ -> _LoadLibrary_ -> _FindResource_. This code path will load the original _TheMatrix_ DLL that does not contain the wanted resource.
  
# Customization
Adding new functions to the monitor is an easy task, have a look at the *hooks.c* file for some example of *Kernel32.dll* and *bcrypt.dll* hooks. To add a new hook is enough to call the function **hook_add**. Below an example of hook creation is shown:
  
 ```
 LPVOID __stdcall hook_BCryptEncrypt(BCRYPT_KEY_HANDLE hKey, PUCHAR pbInput, ULONG cbInput, VOID* pPaddingInfo, PUCHAR pbIV, ULONG cbIV, PUCHAR pbOutput, ULONG cbOutput, ULONG* pcbResult, ULONG dwFlags)
{
	// save plain data
	if (cbInput) {
		char name[MAX_PATH] = { 0 };
		snprintf(name, sizeof(name), "BCryptEncrypt_%llx_%d", (uint64_t)pbInput, cbInput);
		log_data(cbInput, pbInput, name);
	}	

	LPVOID ret = call_original(
		hKey,
		pbInput,
		cbInput,
		pPaddingInfo,
		pbIV,
		cbIV,
		pbOutput,
		cbOutput,
		pcbResult,
		dwFlags
	);
	return ret;
}
  
hook_add("Bcrypt.dll", "BCryptEncrypt", hook_BCryptEncrypt);
```
  
The function must have the same signature of the hooked function. The function **call_original** is used to call the original function. It is enough to call this function with the original function input parameters, the framework will do all the heavy work for you in order to call the correct function ;) The call to the call_original function must be performed in the same thread executing the hook, otherwise the process will crash.

# TODO
* Hook _CreateProcessInternalW_ instead of _CreateProcessW_
* Modify the PEB64 when the process is being executed in WOW64
