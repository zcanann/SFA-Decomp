#include "ghidra_import.h"
#include "main/dll/boulder.h"

extern undefined4 FUN_8000bb38();
extern undefined4 FUN_8002a84c();
extern void* FUN_8002becc();
extern int FUN_8002e088();
extern uint FUN_8002e144();
extern undefined4 FUN_80037da8();
extern undefined4 FUN_80037e24();
extern uint FUN_80286840();
extern undefined4 FUN_8028688c();

extern undefined4 DAT_803dc070;
extern undefined4* DAT_803dd708;
extern f32 FLOAT_803e6b30;
extern f32 FLOAT_803e6b34;
extern f32 FLOAT_803e6b38;

/*
 * --INFO--
 *
 * Function: FUN_801f4ef8
 * EN v1.0 Address: TODO
 * EN v1.0 Size: TODO
 * EN v1.1 Address: 0x801F4EF8
 * EN v1.1 Size: 652b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801f4ef8(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined4 param_9,undefined4 param_10,int param_11,undefined4 param_12,
                 undefined4 param_13,undefined *param_14,int param_15,undefined4 param_16)
{
  uint uVar1;
  uint uVar2;
  undefined2 *puVar3;
  int iVar4;
  int iVar5;
  float *pfVar6;
  double dVar7;
  undefined auStack_28 [40];
  
  uVar2 = FUN_80286840();
  pfVar6 = *(float **)(uVar2 + 0xb8);
  if (*(byte *)((int)pfVar6 + 5) == 0) {
    dVar7 = (double)FUN_8002a84c(uVar2,0);
  }
  else {
    uVar1 = (uint)*(byte *)((int)pfVar6 + 5) + (uint)DAT_803dc070;
    if (0xff < uVar1) {
      uVar1 = 0xff;
    }
    *(char *)((int)pfVar6 + 5) = (char)uVar1;
    dVar7 = (double)FUN_8002a84c(uVar2,(char)uVar1);
  }
  for (iVar5 = 0; iVar5 < (int)(uint)*(byte *)(param_11 + 0x8b); iVar5 = iVar5 + 1) {
    switch(*(undefined *)(param_11 + iVar5 + 0x81)) {
    case 1:
      *(undefined *)(pfVar6 + 1) = 1;
      break;
    case 2:
      *(undefined *)(pfVar6 + 1) = 2;
      param_14 = auStack_28;
      param_15 = *DAT_803dd708;
      (**(code **)(param_15 + 8))(uVar2,0x556,0,2,0xffffffff);
      FUN_8000bb38(uVar2,0x7b);
      dVar7 = (double)FUN_8000bb38(uVar2,0x7c);
      *pfVar6 = FLOAT_803e6b30;
      break;
    case 3:
      *(undefined *)(pfVar6 + 1) = 3;
      param_14 = (undefined *)0x0;
      param_15 = *DAT_803dd708;
      (**(code **)(param_15 + 8))(uVar2,0x556,0,2,0xffffffff);
      FUN_8000bb38(uVar2,0x7b);
      dVar7 = (double)FUN_8000bb38(uVar2,0x7c);
      *pfVar6 = FLOAT_803e6b34;
      break;
    case 4:
      *(undefined *)(pfVar6 + 1) = 0;
      break;
    case 5:
      if ((*(int *)(uVar2 + 200) == 0) && (uVar1 = FUN_8002e144(), (uVar1 & 0xff) != 0)) {
        puVar3 = FUN_8002becc(0x24,0x1b8);
        *(undefined4 *)(puVar3 + 4) = *(undefined4 *)(uVar2 + 0xc);
        *(undefined4 *)(puVar3 + 6) = *(undefined4 *)(uVar2 + 0x10);
        *(undefined4 *)(puVar3 + 8) = *(undefined4 *)(uVar2 + 0x14);
        *(undefined *)(puVar3 + 2) = 0x20;
        *(undefined *)((int)puVar3 + 5) = 4;
        *(undefined *)((int)puVar3 + 7) = 0xff;
        iVar4 = FUN_8002e088(dVar7,param_2,param_3,param_4,param_5,param_6,param_7,param_8,puVar3,5,
                             0xff,0xffffffff,(uint *)0x0,param_14,param_15,param_16);
        FUN_80037e24(uVar2,iVar4,0);
        dVar7 = (double)*(float *)(*(int *)(uVar2 + 200) + 8);
        *(float *)(*(int *)(uVar2 + 200) + 8) = (float)(dVar7 * (double)FLOAT_803e6b38);
      }
      break;
    case 6:
      if (*(int *)(uVar2 + 200) != 0) {
        dVar7 = (double)FUN_80037da8(uVar2,*(int *)(uVar2 + 200));
      }
      break;
    case 7:
      *(byte *)(*(int *)(uVar2 + 0x50) + 0x5f) = *(byte *)(*(int *)(uVar2 + 0x50) + 0x5f) | 0x10;
      *(undefined *)((int)pfVar6 + 5) = 1;
      break;
    case 8:
      *(byte *)(*(int *)(uVar2 + 0x50) + 0x5f) = *(byte *)(*(int *)(uVar2 + 0x50) + 0x5f) & 0xef;
      dVar7 = (double)FUN_8002a84c(uVar2,0);
      *(undefined *)((int)pfVar6 + 5) = 0;
    }
    *(undefined *)(param_11 + iVar5 + 0x81) = 0;
  }
  FUN_8028688c();
  return;
}
