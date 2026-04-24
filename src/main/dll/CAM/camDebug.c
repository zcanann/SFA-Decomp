#include "ghidra_import.h"
#include "main/dll/CAM/camDebug.h"

extern undefined4 FUN_800033a8();
extern undefined4 FUN_800068f4();
extern undefined4 FUN_80017830();

extern undefined4* DAT_803dd6d0;
extern undefined4* DAT_803de1f0;
extern f64 DOUBLE_803e2610;
extern f64 DOUBLE_803e2618;
extern f32 FLOAT_803e2638;
extern f32 FLOAT_803e263c;
extern f32 FLOAT_803e2640;
extern f32 FLOAT_803e2644;
extern f32 FLOAT_803e2648;

/*
 * --INFO--
 *
 * Function: FUN_8010d810
 * EN v1.0 Address: 0x8010D810
 * EN v1.0 Size: 744b
 * EN v1.1 Address: 0x8010DAAC
 * EN v1.1 Size: 720b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8010d810(undefined4 param_1,int param_2,int param_3)
{
  double dVar1;
  int iVar2;
  float local_68;
  undefined4 local_64;
  undefined4 local_60;
  float local_5c;
  float local_58;
  undefined4 local_54;
  undefined auStack_50 [4];
  undefined auStack_4c [4];
  undefined auStack_48 [32];
  undefined8 local_28;
  undefined4 local_20;
  uint uStack_1c;
  
  if (DAT_803de1f0 == (undefined4 *)0x0) {
    DAT_803de1f0 = (undefined4 *)FUN_80017830(0x38,0xf);
  }
  if (param_2 == 2) {
    *(undefined2 *)((int)DAT_803de1f0 + 0x32) = *(undefined2 *)(DAT_803de1f0 + 0xc);
    DAT_803de1f0[7] = DAT_803de1f0[3];
    DAT_803de1f0[9] = DAT_803de1f0[4];
    DAT_803de1f0[5] = *DAT_803de1f0;
    dVar1 = DOUBLE_803e2610;
    *(short *)(DAT_803de1f0 + 0xd) =
         (short)(int)(FLOAT_803e2638 *
                     (float)((double)CONCAT44(0x43300000,(int)*(char *)(param_3 + 3) ^ 0x80000000) -
                            DOUBLE_803e2610));
    DAT_803de1f0[8] =
         (float)((double)CONCAT44(0x43300000,(int)*(char *)(param_3 + 5) ^ 0x80000000) - dVar1);
    local_28 = (double)CONCAT44(0x43300000,(int)*(char *)(param_3 + 4) ^ 0x80000000);
    DAT_803de1f0[10] = (float)(local_28 - dVar1);
    DAT_803de1f0[6] =
         (float)((double)CONCAT44(0x43300000,(int)*(char *)(param_3 + 2) ^ 0x80000000) - dVar1);
    *(short *)(DAT_803de1f0 + 0xb) = (short)*(char *)(param_3 + 1);
    *(short *)((int)DAT_803de1f0 + 0x2e) = (short)*(char *)(param_3 + 1);
  }
  else {
    FUN_800033a8((int)DAT_803de1f0,0,0x38);
    iVar2 = (**(code **)(*DAT_803dd6d0 + 0x18))();
    (**(code **)(**(int **)(iVar2 + 4) + 0x20))(&local_58,&local_5c,&local_60,&local_64,&local_68);
    uStack_1c = (uint)*(ushort *)(DAT_803de1f0 + 0xc);
    local_20 = 0x43300000;
    (**(code **)(*DAT_803dd6d0 + 0x38))
              ((double)(float)((double)CONCAT44(0x43300000,uStack_1c) - DOUBLE_803e2618),param_1,
               auStack_48,auStack_4c,auStack_50,&local_54,0);
    *(short *)((int)DAT_803de1f0 + 0x32) = (short)(int)local_68;
    DAT_803de1f0[7] = local_60;
    DAT_803de1f0[9] = local_64;
    DAT_803de1f0[5] = local_54;
    *(undefined2 *)(DAT_803de1f0 + 0xd) = 0x1e;
    DAT_803de1f0[8] = FLOAT_803e263c;
    DAT_803de1f0[10] = FLOAT_803e2640;
    DAT_803de1f0[6] = FLOAT_803e2644 * (local_5c + local_58);
    *(undefined2 *)(DAT_803de1f0 + 0xb) = 0x3c;
    *(undefined2 *)((int)DAT_803de1f0 + 0x2e) = 0x3c;
    DAT_803de1f0[1] = local_54;
    DAT_803de1f0[2] = FLOAT_803e2648;
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8010daf8
 * EN v1.0 Address: 0x8010DAF8
 * EN v1.0 Size: 144b
 * EN v1.1 Address: 0x8010DD7C
 * EN v1.1 Size: 156b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8010daf8(undefined2 *param_1,undefined4 param_2,undefined2 *param_3)
{
  if (param_3 != (undefined2 *)0x0) {
    *(undefined4 *)(param_1 + 0xc) = *(undefined4 *)(param_3 + 0xc);
    *(undefined4 *)(param_1 + 0xe) = *(undefined4 *)(param_3 + 0xe);
    *(undefined4 *)(param_1 + 0x10) = *(undefined4 *)(param_3 + 0x10);
    FUN_800068f4((double)*(float *)(param_3 + 0xc),(double)*(float *)(param_3 + 0xe),
                 (double)*(float *)(param_3 + 0x10),(float *)(param_1 + 6),(float *)(param_1 + 8),
                 (float *)(param_1 + 10),*(int *)(param_1 + 0x18));
    *param_1 = *param_3;
    param_1[1] = param_3[1];
    param_1[2] = param_3[2];
    *(undefined4 *)(param_1 + 0x5a) = *(undefined4 *)(param_3 + 0x5a);
  }
  return;
}
