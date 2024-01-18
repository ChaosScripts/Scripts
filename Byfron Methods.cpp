/* Methods
    Indirect SysCalls?
    Kernel Driver
    Trampoline Hooking and Hiding in plain sight
*/

#include "Header.h" // header specific information

_declspec(naked) void _return() /*
  Expects Inline asm and explicitly declares the function naked which means cleaning and setting up the function is up to you
  also is a wrapper that returns void
/*
{
	_asm
	{
		xor eax, eax ; clean eax // why not just use ecx?
		dec eax ; -1?
		push eax ; push eax as the first parameter to exit process // process exited with failure?
		call ExitProcess 
	}
}

_declspec(naked) void FakeFunction() ; newclosure
{
	__asm
	{
		push ebp ; setup the stack frame
		mov ebp, esp
		push 0 ; setting up parameters
		push Lcp
		push Lxt
		push MB_OK ; status code
		call MessageBoxA ; parameters > 1: 0; 2: Lcp[offset]: 3: Lxt[offset]: 4: [Status code // Macro or Enum?]
		pop ebp ; pop ebp into esp // restores the previous stackframe
		ret ; return from subruetine // cpu pops the return address into ip
	}
}

int __stdcall IntereceptCalls(HWND hWnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType) 
{ // standard call that intercepts function calls, returns a integer
	__asm
	{
		push    lpText ; print this
		call    printf
		push    lpCaption ; print this
		call    printf
		push    dt ; print this
		call	printf
		add     esp, 12 ; allocate 12 bytes to the stack
	}
	// write to current process
	WriteProcessMemory(GetCurrentProcess(), (LPVOID)originalAdd, originalbytes, sizeof(originalbytes), NULL);

	__asm
	{
		push 0 ; setup parameters for function call
		push Lcp
		push Lxt
		push MB_OK
		call MessageBoxA
	}

	__asm
	{
		; set up parameters
		push hWnd ; push the offset to the window handle
		push lpText 
		push lpCaption
		push uType
		call MessageBoxA
	}
	// Write to current process
	WriteProcessMemory(GetCurrentProcess(), originalAdd, patchOpcodes, sizeof(patchOpcodes), NULL);
	
	return 0; // success
}

int wmain()
{
	HMODULE library = LoadLibraryA("user32.dll"); // grab a handle to user32dll

	// grab the address of the MessageBoxA method in the user32 dll
	originalAdd = GetProcAddress(library, "MessageBoxA");
	if (!originalAdd)
	{
		__asm
		{
			call _return ; call our wrapper
		}
	}

	// read memory from our current process
	ReadProcessMemory(GetCurrentProcess(), originalAdd, originalbytes, 6, &nobytes);
	__asm
	{
		cmp eax, 0 ; cmp eax against 0 // would be better to use test eax(faster), eax but it dosent matter
		je _return ; je eflag set if eax is 0, if then jump to our wrapper	
	}

	vfunc = &IntereceptCalls; // virtual function InterceptCalls
	memcpy_s(patchOpcodes + 2, 4, &vfunc, 4); // copy our vfunction into opcodes pos + 2 2 bytes down the stack frame

	// write memory into our current process
	WriteProcessMemory(GetCurrentProcess(), originalAdd, patchOpcodes, sizeof(patchOpcodes), NULL);
	__asm
	{
		cmp eax, 0 ; compare eax against 0
		je _return ; if eax is 0 jump to our wrapper
	}

	MessageBoxA(NULL, "alert 1", "HELLO 1", MB_OK); // call message boxes
	MessageBoxA(NULL, "alert 2", "HELLO 2", MB_OK); // call message boxes
	MessageBoxA(NULL, "alert 3", "HELLO 3", MB_OK); // call message boxes
	__asm
	{
		call __return ; call our wrapper
	}
}
