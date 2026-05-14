#include "ghidra_import.h"
#include "main/dll/WC/WCfloortile.h"

extern undefined4 FUN_80017a7c();
extern undefined4 FUN_8003b818();
extern undefined4 FUN_800631d4();
extern undefined4 WM_Galleon_update();

extern undefined4* DAT_803dd72c;

/*
 * --INFO--
 *
 * Function: FUN_801f0b50
 * EN v1.0 Address: 0x801F0B50
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x801F0C0C
 * EN v1.1 Size: 356b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801f0b50(undefined2 *param_1,int param_2)
{
}

/*
 * --INFO--
 *
 * Function: FUN_801f0b54
 * EN v1.0 Address: 0x801F0B54
 * EN v1.0 Size: 40b
 * EN v1.1 Address: 0x801F0D70
 * EN v1.1 Size: 52b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801f0b54(int param_1)
{
  char in_r8;
  
  if (in_r8 != '\0') {
    FUN_8003b818(param_1);
  }
  return;
}
