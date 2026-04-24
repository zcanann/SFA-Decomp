#include "ghidra_import.h"
#include "main/dll/creator1D6.h"

extern undefined4 FUN_8000680c();
extern uint FUN_80017690();
extern undefined4 FUN_80017698();
extern int FUN_80017a90();
extern undefined4 FUN_8003735c();
extern undefined4 FUN_801ce244();

extern undefined4 DAT_80327428;
extern undefined4 DAT_80327458;
extern undefined4* DAT_803dd6e8;
extern undefined4* DAT_803dd71c;
extern undefined4* DAT_803dd728;
extern undefined4 DAT_803e5ea0;
extern f32 FLOAT_803e5ee4;
extern f32 FLOAT_803e5eec;
extern f32 FLOAT_803e5ef0;

/*
 * --INFO--
 *
 * Function: FUN_801cf7e8
 * EN v1.0 Address: 0x801CF7E8
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x801CFAC0
 * EN v1.1 Size: 668b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801cf7e8(undefined2 *param_1,int param_2,int param_3)
{
}

/*
 * --INFO--
 *
 * Function: FUN_801cf7ec
 * EN v1.0 Address: 0x801CF7EC
 * EN v1.0 Size: 44b
 * EN v1.1 Address: 0x801CFD5C
 * EN v1.1 Size: 52b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_801cf7ec(void)
{
  int iVar1;
  
  iVar1 = FUN_80017a90();
  FUN_8000680c(iVar1,0x10);
  return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_801cf818
 * EN v1.0 Address: 0x801CF818
 * EN v1.0 Size: 40b
 * EN v1.1 Address: 0x801CFD90
 * EN v1.1 Size: 40b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801cf818(void)
{
  FUN_80017698(0x4e4,1);
  return;
}
