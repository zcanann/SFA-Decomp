#include "ghidra_import.h"
#include "main/dll/dll_182.h"

extern uint FUN_80020078();
extern undefined4 FUN_800201ac();
extern undefined4 FUN_800395a4();
extern undefined4 FUN_8003b9ec();
extern undefined4 FUN_800979c0();

extern f64 DOUBLE_803e4bc0;
extern f32 FLOAT_803e4b98;
extern f32 FLOAT_803e4b9c;
extern f32 FLOAT_803e4ba0;
extern f32 FLOAT_803e4ba4;
extern f32 FLOAT_803e4ba8;
extern f32 FLOAT_803e4bac;
extern f32 FLOAT_803e4bb0;
extern f32 FLOAT_803e4bb4;
extern f32 FLOAT_803e4bb8;
extern f32 FLOAT_803e4bbc;

/*
 * --INFO--
 *
 * Function: FUN_801920f0
 * EN v1.0 Address: TODO
 * EN v1.0 Size: TODO
 * EN v1.1 Address: 0x801920F0
 * EN v1.1 Size: 40b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801920f0(int param_1)
{
  FUN_8003b9ec(param_1);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80192118
 * EN v1.0 Address: TODO
 * EN v1.0 Size: TODO
 * EN v1.1 Address: 0x80192118
 * EN v1.1 Size: 180b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80192118(int param_1)
{
  undefined auStack_18 [12];
  float local_c;
  float local_8;
  float local_4;
  
  if (*(short *)(param_1 + 0x46) == 0x79) {
    local_c = FLOAT_803e4b9c;
    local_8 = FLOAT_803e4ba0;
    local_4 = FLOAT_803e4b9c;
    FUN_800979c0((double)FLOAT_803e4ba4,(double)FLOAT_803e4ba8,(double)FLOAT_803e4ba8,
                 (double)FLOAT_803e4bac,param_1,5,5,2,0x19,(int)auStack_18,0);
  }
  else if (*(short *)(param_1 + 0x46) == 0x748) {
    local_c = FLOAT_803e4b9c;
    local_8 = FLOAT_803e4bb0;
    local_4 = FLOAT_803e4b9c;
    FUN_800979c0((double)FLOAT_803e4bb4,(double)FLOAT_803e4bb8,(double)FLOAT_803e4bb8,
                 (double)FLOAT_803e4bac,param_1,5,5,2,5,(int)auStack_18,0);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801921cc
 * EN v1.0 Address: TODO
 * EN v1.0 Size: TODO
 * EN v1.1 Address: 0x801921CC
 * EN v1.1 Size: 204b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801921cc(short *param_1,int param_2)
{
  param_1[2] = (ushort)*(byte *)(param_2 + 0x18) << 8;
  param_1[1] = (ushort)*(byte *)(param_2 + 0x19) << 8;
  *param_1 = (ushort)*(byte *)(param_2 + 0x1a) << 8;
  if (*(byte *)(param_2 + 0x1b) != 0) {
    *(float *)(param_1 + 4) =
         (float)((double)CONCAT44(0x43300000,(uint)*(byte *)(param_2 + 0x1b)) - DOUBLE_803e4bc0) /
         FLOAT_803e4bbc;
    if (*(float *)(param_1 + 4) == FLOAT_803e4b9c) {
      *(float *)(param_1 + 4) = FLOAT_803e4b98;
    }
    *(float *)(param_1 + 4) = *(float *)(param_1 + 4) * *(float *)(*(int *)(param_1 + 0x28) + 4);
  }
  param_1[0x58] = param_1[0x58] | 0x2000;
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80192298
 * EN v1.0 Address: TODO
 * EN v1.0 Size: TODO
 * EN v1.1 Address: 0x80192298
 * EN v1.1 Size: 308b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80192298(int param_1)
{
  uint uVar1;
  uint *puVar2;
  int iVar3;
  uint *puVar4;
  
  puVar4 = *(uint **)(param_1 + 0xb8);
  iVar3 = *(int *)(param_1 + 0x4c);
  if ((((*(byte *)(puVar4 + 5) >> 5 & 1) == 0) &&
      (uVar1 = FUN_80020078((int)*(short *)(iVar3 + 0x20)), uVar1 != 0)) &&
     ((*(byte *)(puVar4 + 5) >> 6 & 1) == 0)) {
    *(byte *)(puVar4 + 5) = *(byte *)(puVar4 + 5) & 0xdf | 0x20;
    puVar4[4] = 0;
  }
  if (((*(byte *)(puVar4 + 5) >> 5 & 1) != 0) &&
     (puVar2 = (uint *)FUN_800395a4(param_1,*puVar4), puVar2 != (uint *)0x0)) {
    puVar4[4] = puVar4[4] + (uint)*(byte *)(puVar4 + 1);
    if ((int)puVar4[4] < 0) {
      puVar4[4] = 0;
    }
    else if ((int)puVar4[2] < (int)puVar4[4]) {
      uVar1 = (uint)*(short *)(iVar3 + 0x1e);
      if (uVar1 == 0xffffffff) {
        puVar4[4] = puVar4[3];
      }
      else {
        FUN_800201ac(uVar1,1);
        *(byte *)(puVar4 + 5) = *(byte *)(puVar4 + 5) & 0xdf;
        *(byte *)(puVar4 + 5) = *(byte *)(puVar4 + 5) & 0xbf | 0x40;
        puVar4[4] = puVar4[2];
      }
    }
    *puVar2 = puVar4[4];
  }
  return;
}
