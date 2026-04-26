#include "ghidra_import.h"
#include "main/dll/dll_8B.h"

extern u8 *lbl_803DD524;
extern s16 lbl_803DB990;

/*
 * --INFO--
 *
 * Function: fn_80100A8C
 * EN v1.0 Address: 0x80100A8C
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80100A8C
 * EN v1.1 Size: 4b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void fn_80100A8C(void)
{
}

/*
 * --INFO--
 *
 * Function: fn_80100A90
 * EN v1.0 Address: 0x80100A90
 * EN v1.0 Size: 12b
 */
u8 fn_80100A90(void)
{
  return lbl_803DD524[0x138];
}

/*
 * --INFO--
 *
 * Function: fn_80100A9C
 * EN v1.0 Address: 0x80100A9C
 * EN v1.0 Size: 8b
 */
s16 fn_80100A9C(void)
{
  return lbl_803DB990;
}
