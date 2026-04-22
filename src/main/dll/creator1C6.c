#include "ghidra_import.h"
#include "main/dll/creator1C6.h"

extern undefined4 FUN_80021754();
extern uint FUN_80021884();
extern uint FUN_80022264();
extern int FUN_8002bac4();
extern undefined4 FUN_8002fb40();
extern undefined4 FUN_80035eec();
extern undefined4 FUN_80035f9c();
extern undefined4 FUN_80036018();
extern undefined4 FUN_80036f50();
extern undefined4 FUN_802945e0();

extern undefined4 DAT_803de848;
extern f64 DOUBLE_803e5d28;
extern f64 DOUBLE_803e5d68;
extern f32 FLOAT_803dc074;
extern f32 FLOAT_803e5cfc;
extern f32 FLOAT_803e5d00;
extern f32 FLOAT_803e5d1c;
extern f32 FLOAT_803e5d38;
extern f32 FLOAT_803e5d3c;
extern f32 FLOAT_803e5d40;
extern f32 FLOAT_803e5d44;
extern f32 FLOAT_803e5d50;
extern f32 FLOAT_803e5d54;
extern f32 FLOAT_803e5d58;
extern f32 FLOAT_803e5d5c;
extern f32 FLOAT_803e5d60;

/*
 * --INFO--
 *
 * Function: FUN_801c8fe8
 * EN v1.0 Address: 0x801C8FE8
 * EN v1.0 Size: 308b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801c8fe8(int param_1,int param_2)
{
  float fVar1;
  uint uVar2;
  undefined4 *puVar3;
  float local_18 [2];
  undefined4 local_10;
  uint uStack_c;
  
  puVar3 = *(undefined4 **)(param_1 + 0xb8);
  local_18[0] = FLOAT_803e5cfc;
  DAT_803de848 = 0;
  *puVar3 = *(undefined4 *)(param_1 + 0xc);
  puVar3[1] = *(undefined4 *)(param_1 + 0x10);
  puVar3[2] = *(undefined4 *)(param_1 + 0x14);
  puVar3[6] = *(undefined4 *)(param_1 + 0x10);
  *(float *)(param_1 + 0x10) = *(float *)(param_1 + 0x10) - FLOAT_803e5d1c;
  fVar1 = FLOAT_803e5d00;
  puVar3[3] = FLOAT_803e5d00;
  puVar3[4] = fVar1;
  puVar3[5] = fVar1;
  puVar3[9] = 0;
  puVar3[10] = (int)*(short *)(param_2 + 0x1a);
  uStack_c = FUN_80022264(0,600);
  uStack_c = uStack_c ^ 0x80000000;
  local_10 = 0x43300000;
  puVar3[8] = (float)((double)CONCAT44(0x43300000,uStack_c) - DOUBLE_803e5d28);
  uVar2 = FUN_80022264(0xfffffce0,800);
  *(short *)(puVar3 + 0xb) = (short)uVar2;
  *(undefined *)((int)puVar3 + 0x2e) = 1;
  *(undefined *)(param_1 + 0x37) = 0;
  puVar3[7] = FLOAT_803e5d00;
  if (DAT_803de848 == 0) {
    DAT_803de848 = FUN_80036f50(0xb,param_1,local_18);
  }
  FUN_80036018(param_1);
  FUN_80035eec(param_1,0,0,0);
  FUN_80035f9c(param_1);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801c911c
 * EN v1.0 Address: 0x801C911C
 * EN v1.0 Size: 852b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801c911c(ushort *param_1)
{
  int iVar1;
  uint uVar2;
  int iVar3;
  int iVar4;
  double dVar5;
  double dVar6;
  undefined8 local_30;
  
  iVar4 = *(int *)(param_1 + 0x26);
  iVar3 = *(int *)(param_1 + 0x5c);
  iVar1 = FUN_8002bac4();
  if ((param_1[3] & 0x4000) == 0) {
    *(short *)(iVar3 + 0xe) =
         *(short *)(iVar3 + 0xe) + (short)(int)(FLOAT_803e5d38 * FLOAT_803dc074);
    *(short *)(iVar3 + 0x10) =
         *(short *)(iVar3 + 0x10) + (short)(int)(FLOAT_803e5d3c * FLOAT_803dc074);
    *(short *)(iVar3 + 0x12) =
         *(short *)(iVar3 + 0x12) + (short)(int)(FLOAT_803e5d40 * FLOAT_803dc074);
    dVar5 = (double)FUN_802945e0();
    *(float *)(param_1 + 8) = FLOAT_803e5d44 + (float)((double)*(float *)(iVar4 + 0xc) + dVar5);
    dVar5 = (double)FUN_802945e0();
    dVar6 = (double)FUN_802945e0();
    param_1[2] = (ushort)(int)(FLOAT_803e5d50 * (float)(dVar6 + dVar5));
    dVar5 = (double)FUN_802945e0();
    dVar6 = (double)FUN_802945e0();
    param_1[1] = (ushort)(int)(FLOAT_803e5d50 * (float)(dVar6 + dVar5));
    FUN_8002fb40((double)FLOAT_803e5d54,(double)FLOAT_803dc074);
    if (iVar1 != 0) {
      uVar2 = FUN_80021884();
      uVar2 = (uVar2 & 0xffff) - (uint)*param_1;
      if (0x8000 < (int)uVar2) {
        uVar2 = uVar2 - 0xffff;
      }
      if ((int)uVar2 < -0x8000) {
        uVar2 = uVar2 + 0xffff;
      }
      local_30 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      *param_1 = *param_1 +
                 (short)(int)(((float)(local_30 - DOUBLE_803e5d68) * FLOAT_803dc074) /
                             FLOAT_803e5d58);
      dVar5 = (double)FUN_80021754((float *)(param_1 + 0xc),(float *)(iVar1 + 0x18));
      if ((double)FLOAT_803e5d5c < dVar5) {
        *(undefined *)(param_1 + 0x1b) = 0xff;
      }
      else {
        *(char *)(param_1 + 0x1b) =
             (char)(int)(FLOAT_803e5d60 * (float)(dVar5 / (double)FLOAT_803e5d5c));
      }
    }
  }
  else {
    *param_1 = 0;
    *(undefined4 *)(param_1 + 8) = *(undefined4 *)(iVar4 + 0xc);
  }
  return;
}
