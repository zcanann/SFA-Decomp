#include "ghidra_import.h"
#include "main/dll/WM/WMlevcontrol.h"

extern uint FUN_80020078();
extern undefined4 FUN_8002b9a0();

extern undefined4* DAT_803dd6d4;
extern f64 DOUBLE_803e6280;
extern f32 FLOAT_803e6278;

/*
 * --INFO--
 *
 * Function: FUN_801dd600
 * EN v1.0 Address: 0x801DD46C
 * EN v1.0 Size: 376b
 * EN v1.1 Address: 0x801DD600
 * EN v1.1 Size: 352b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801dd600(int param_1,int param_2)
{
  int iVar1;
  int iVar2;
  
  FUN_8002b9a0(param_1,'d');
  iVar2 = *(int *)(param_1 + 0xb8);
  *(undefined2 *)(iVar2 + 0x6a) = *(undefined2 *)(param_2 + 0x1a);
  *(undefined2 *)(iVar2 + 0x6e) = 0xffff;
  *(float *)(iVar2 + 0x24) =
       FLOAT_803e6278 /
       (FLOAT_803e6278 +
       (float)((double)CONCAT44(0x43300000,(uint)*(byte *)(param_2 + 0x24)) - DOUBLE_803e6280));
  *(undefined4 *)(iVar2 + 0x28) = 0xffffffff;
  *(undefined4 *)(param_1 + 0xf8) = 0;
  iVar1 = *(int *)(param_1 + 0xf4);
  if ((iVar1 == 0) && (*(short *)(param_2 + 0x18) != 1)) {
    (**(code **)(*DAT_803dd6d4 + 0x1c))(iVar2,param_2);
    *(int *)(param_1 + 0xf4) = *(short *)(param_2 + 0x18) + 1;
  }
  else if ((iVar1 != 0) && ((int)*(short *)(param_2 + 0x18) != iVar1 + -1)) {
    (**(code **)(*DAT_803dd6d4 + 0x24))(iVar2);
    if (*(short *)(param_2 + 0x18) != -1) {
      (**(code **)(*DAT_803dd6d4 + 0x1c))(iVar2,param_2);
    }
    *(int *)(param_1 + 0xf4) = *(short *)(param_2 + 0x18) + 1;
  }
  if (*(int *)(param_1 + 100) != 0) {
    *(undefined *)(*(int *)(param_1 + 100) + 0x3a) = 100;
    *(undefined *)(*(int *)(param_1 + 100) + 0x3b) = 0x96;
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801dd760
 * EN v1.0 Address: 0x801DD5E4
 * EN v1.0 Size: 44b
 * EN v1.1 Address: 0x801DD760
 * EN v1.1 Size: 56b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
bool FUN_801dd760(void)
{
  uint uVar1;
  
  uVar1 = FUN_80020078(0x639);
  return uVar1 == 0;
}
