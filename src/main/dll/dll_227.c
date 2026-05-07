#include "ghidra_import.h"
#include "main/dll/dll_227.h"

extern void *lbl_803DCA8C;
extern int lbl_803DDBB0;

/*
 * --INFO--
 *
 * Function: dimbosstonsil_hitDetect
 * EN v1.0 Address: 0x801BEA3C
 * EN v1.0 Size: 56b
 */
#pragma peephole off
#pragma scheduling off
void dimbosstonsil_hitDetect(void *obj)
{
    (*(void (***)(void *, void *, int *))lbl_803DCA8C)[3](obj, *(void **)((char *)obj + 0xb8), &lbl_803DDBB0);
}
#pragma scheduling reset
#pragma peephole reset
