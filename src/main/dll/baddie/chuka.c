#include "ghidra_import.h"
#include "main/dll/baddie/chuka.h"

extern undefined4 FUN_80006b14();

extern undefined4* DAT_803dd6f8;
extern f64 DOUBLE_803e7088;
extern f32 FLOAT_803e7078;
extern f32 FLOAT_803e707c;
extern f32 FLOAT_803e7080;

/*
 * --INFO--
 *
 * Function: chuka_init
 * EN v1.0 Address: 0x8020637C
 * EN v1.0 Size: 260b
 * EN v1.1 Address: 0x80206444
 * EN v1.1 Size: 332b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void chuka_init(undefined2 *param_1,int param_2)
{
  int *piVar1;
  int *piVar2;
  undefined auStack_38 [16];
  float local_28;
  undefined4 local_20;
  uint uStack_1c;
  
  piVar2 = *(int **)(param_1 + 0x5c);
  *param_1 = (short)(((int)*(char *)(param_2 + 0x18) & 0x3fU) << 10);
  if (*(short *)(param_2 + 0x1a) < 1) {
    *(float *)(param_1 + 4) = FLOAT_803e7080;
  }
  else {
    uStack_1c = (int)*(short *)(param_2 + 0x1a) ^ 0x80000000;
    local_20 = 0x43300000;
    *(float *)(param_1 + 4) =
         (float)((double)CONCAT44(0x43300000,uStack_1c) - DOUBLE_803e7088) / FLOAT_803e707c;
  }
  *(undefined *)((int)piVar2 + 9) = *(undefined *)(param_2 + 0x19);
  *piVar2 = (int)*(short *)(param_2 + 0x1e);
  local_28 = FLOAT_803e7078;
  if (*(char *)((int)piVar2 + 9) == '\0') {
    *(undefined *)((int)piVar2 + 10) = 1;
    piVar1 = (int *)FUN_80006b14(0x69);
    if (*(short *)(param_2 + 0x1c) == 0) {
      (**(code **)(*piVar1 + 4))(param_1,0,auStack_38,0x10004,0xffffffff,0);
    }
  }
  *(char *)((int)piVar2 + 0xd) = (char)*(undefined2 *)(param_2 + 0x1c);
  param_1[0x58] = param_1[0x58] | 0x2000;
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80206480
 * EN v1.0 Address: 0x80206480
 * EN v1.0 Size: 52b
 * EN v1.1 Address: 0x80206590
 * EN v1.1 Size: 96b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80206480(void)
{
  (**(code **)(*DAT_803dd6f8 + 0x18))();
  return;
}

/*
 * --INFO--
 *
 * Function: chuka_release
 * EN v1.0 Address: 0x8020646C
 * EN v1.0 Size: 4b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void chuka_release(void)
{
}

/*
 * --INFO--
 *
 * Function: chuka_initialise
 * EN v1.0 Address: 0x80206470
 * EN v1.0 Size: 4b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void chuka_initialise(void)
{
}

/*
 * --INFO--
 *
 * Function: dfpfloorbar_getExtraSize
 * EN v1.0 Address: 0x8020647C
 * EN v1.0 Size: 8b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int dfpfloorbar_getExtraSize(void)
{
  return 0xc;
}
