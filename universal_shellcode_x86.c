#include <stdio.h>
#include <Windows.h>

int main(void)
{
	printf("shellcode");

	__asm {
		jmp start

	find_addr:
		xor ecx, ecx
		dec ecx

	get_name:
		inc ecx
		xor edx, edx
		mov esi, [esp+0x8]
		lea esi, [esi+ecx*4]
		lodsd
		add eax, [esp+0x18]
		mov esi, eax

	loop_hash:
		mov eax, esi
		xor eax, eax
		lodsb
		add edx, eax
		test al, al
		jnz loop_hash
		cmp edx, [esp+0x4]
		jne get_name
		mov edi, [esp+0xc]
		xor edx, edx
		mov dx, [edi+ecx*2]
		mov esi, [esp+0x1c]
		mov esi, [esi+edx*4]
		add esi, [esp+0x18]
		mov eax, esi
		ret

	start:
		xor edx, edx
		mov dl, 0x30
		mov eax, fs:[edx]
		mov eax, [eax+0xc]
		mov ebx, [eax+0x14]
		mov ebx, [ebx]
		mov ebx, [ebx]
		mov ebx, [ebx+0x10] //kernel32.dll base

		mov edx, ebx
		add dx, 0x168
		mov edi, edx
		mov ecx, [edi] 
		add ecx, ebx //IMAGE_OPTIONAL_HEADER

		mov edx, [ecx+0x1c]
		add edx, ebx //Address Table
		mov edi, [ecx+0x20]
		add edi, ebx //Name Pointer Table
		mov esi, [ecx+0x24]
		add esi, ebx //Ordinal Table
		pushad
		xor edi, edi
		mov di, 0x2b3 //WinExec hash
		push edi
		call find_addr
		mov edi, 0x636c6163
		push edi
		xor edx, edx
		mov [esp+0x4], edx
		push esp
		call eax

		add sp, 4
		popad
		pushad
		xor edi, edi
		mov di, 0x479
		push edi
		call find_addr
		xor edx, edx
		push edx
		call eax
	}

	/*char shellcode[] = "\xEB\x3D\x33\xC9\x49\x41\x33\xD2\x8B\x74\x24\x08"
	"\x8D\x34\x8E\xAD\x03\x44\x24\x18\x8B\xF0\x8B\xC6\x33\xC0\xAC\x03\xD0"
	"\x84\xC0\x75\xF5\x3B\x54\x24\x04\x75\xDE\x8B\x7C\x24\x0C\x33\xD2\x66"
	"\x8B\x14\x4F\x8B\x74\x24\x1C\x8B\x34\x96\x03\x74\x24\x18\x8B\xC6\xC3"
	"\x33\xD2\xB2\x30\x64\x8B\x02\x8B\x40\x0C\x8B\x58\x14\x8B\x1B\x8B\x1B"
	"\x8B\x5B\x10\x8B\xD3\x66\x81\xC2\x68\x01\x8B\xFA\x8B\x0F\x03\xCB\x8B"
	"\x51\x1C\x03\xD3\x8B\x79\x20\x03\xFB\x8B\x71\x24\x03\xF3\x60\x33\xFF"
	"\x66\xBF\xB3\x02\x57\xE8\x86\xFF\xFF\xFF\xBF\x63\x61\x6C\x63\x57\x33"
	"\xD2\x89\x54\x24\x04\x54\xFF\xD0\x66\x83\xC4\x04\x61\x60\x33\xFF\x66"
	"\xBF\x79\x04\x57\xE8\x65\xFF\xFF\xFF\x33\xD2\x52\xFF\xD0";

	int* shell = (int*)shellcode;

	__asm
	{
		jmp shell
	}*/

	return 0;
}
