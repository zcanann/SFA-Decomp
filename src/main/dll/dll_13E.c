#include "ghidra_import.h"
#include "main/dll/dll_13E.h"

extern undefined8 FUN_8000bb38();
extern uint FUN_80014e9c();
extern undefined4 FUN_80021b8c();
extern undefined4 FUN_8002bac4();
extern undefined4 FUN_80035f9c();
extern undefined8 FUN_80035ff8();
extern undefined4 FUN_80036018();
extern undefined4 FUN_800379bc();
extern undefined4 FUN_8011f68c();
extern uint FUN_80296350();
extern uint FUN_80296dfc();

extern undefined4* DAT_803dd728;
extern f32 FLOAT_803e4320;
extern f32 FLOAT_803e4324;
extern f32 FLOAT_803e4328;
extern f32 FLOAT_803e432c;
extern f32 FLOAT_803e4330;
extern f32 FLOAT_803e4334;
extern f32 FLOAT_803e4338;
extern f32 FLOAT_803e433c;

/*
 * --INFO--
 *
 * Function: FUN_80179864
 * EN v1.0 Address: TODO
 * EN v1.0 Size: TODO
 * EN v1.1 Address: 0x80179864
 * EN v1.1 Size: 656b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80179864(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 uint param_9,int param_10,undefined4 param_11,undefined4 param_12,
                 undefined4 param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16)
{
  float fVar1;
  float fVar2;
  undefined4 uVar3;
  ushort *puVar4;
  uint uVar5;
  int iVar6;
  undefined8 uVar7;
  short local_38 [2];
  ushort local_34 [4];
  float local_2c;
  float local_28;
  float local_24;
  float local_20;
  
  puVar4 = (ushort *)FUN_8002bac4();
  iVar6 = *(int *)(puVar4 + 0x5c);
  if (*(char *)(param_10 + 0x2c8) != '\x01') {
    if (*(char *)(param_10 + 0x2c9) == '\0') {
      *(undefined *)(param_10 + 0x2c9) = 1;
      if (*(char *)(param_10 + 0x2c9) != '\0') {
        *(undefined *)(param_10 + 0x2ca) = 1;
      }
    }
    else {
      uVar7 = FUN_80035ff8(param_9);
      *(byte *)(param_9 + 0xaf) = *(byte *)(param_9 + 0xaf) | 8;
      FUN_8011f68c(local_38);
      uVar5 = FUN_80014e9c(0);
      if (((uVar5 & 0x100) != 0) ||
         ((local_38[0] == 5 && (uVar5 = FUN_80014e9c(0), (uVar5 & 0x800) != 0)))) {
        uVar5 = FUN_80296350((int)puVar4);
        if (uVar5 == 0) {
          uVar7 = FUN_8000bb38(0,0x10a);
        }
        else {
          *(undefined *)(param_10 + 0x2ca) = 0;
        }
      }
      if (*(int *)(param_9 + 0xf8) == 1) {
        *(undefined *)(param_10 + 0x2c9) = 2;
      }
      if ((*(char *)(param_10 + 0x2c9) == '\x02') && (*(int *)(param_9 + 0xf8) == 0)) {
        uVar5 = FUN_80296dfc((int)puVar4);
        if (uVar5 == 0) {
          *(undefined *)(param_10 + 0x2c9) = 0;
          *(undefined *)(param_10 + 0x2ca) = 0;
          *(float *)(param_10 + 0x26c) = FLOAT_803e433c;
          *(undefined *)(param_10 + 0x274) = 5;
        }
        else {
          *(undefined *)(param_10 + 0x2c9) = 0;
          *(undefined *)(param_10 + 0x2c8) = 1;
          fVar1 = FLOAT_803e4320;
          *(float *)(param_9 + 0x28) =
               FLOAT_803e4320 * (FLOAT_803e4328 * *(float *)(iVar6 + 0x298) + FLOAT_803e4324);
          *(float *)(param_9 + 0x2c) =
               fVar1 * (FLOAT_803e4330 * *(float *)(iVar6 + 0x298) + FLOAT_803e432c);
          local_28 = FLOAT_803e4334;
          local_24 = FLOAT_803e4334;
          local_20 = FLOAT_803e4334;
          local_2c = FLOAT_803e4338;
          local_34[2] = 0;
          local_34[1] = 0;
          if (*(short **)(puVar4 + 0x18) == (short *)0x0) {
            local_34[0] = *puVar4;
          }
          else {
            local_34[0] = **(short **)(puVar4 + 0x18) + *puVar4;
          }
          FUN_80021b8c(local_34,(float *)(param_9 + 0x24));
          fVar1 = *(float *)(param_9 + 0x2c);
          param_3 = (double)fVar1;
          fVar2 = *(float *)(param_9 + 0x28);
          param_2 = (double)fVar2;
          uVar3 = *(undefined4 *)(param_9 + 0x24);
          iVar6 = *(int *)(param_9 + 0xb8);
          *(undefined *)(iVar6 + 0x274) = 3;
          *(float *)(iVar6 + 0x26c) = FLOAT_803e4334;
          *(undefined4 *)(param_9 + 0x24) = uVar3;
          *(float *)(param_9 + 0x28) = fVar2;
          *(float *)(param_9 + 0x2c) = fVar1;
          FUN_80036018(param_9);
          FUN_80035f9c(param_9);
          *(undefined *)(iVar6 + 0x25b) = 1;
          *(undefined4 *)(iVar6 + 0x2b0) = *(undefined4 *)(param_9 + 0xc);
          *(undefined4 *)(iVar6 + 0x2b4) = *(undefined4 *)(param_9 + 0x10);
          *(undefined4 *)(iVar6 + 0x2b8) = *(undefined4 *)(param_9 + 0x14);
          uVar7 = (**(code **)(*DAT_803dd728 + 0x20))(param_9,iVar6);
        }
      }
      if (*(char *)(param_10 + 0x2ca) != '\0') {
        FUN_800379bc(uVar7,param_2,param_3,param_4,param_5,param_6,param_7,param_8,(int)puVar4,
                     0x100010,param_9,0,param_13,param_14,param_15,param_16);
      }
    }
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80179af4
 * EN v1.0 Address: TODO
 * EN v1.0 Size: TODO
 * EN v1.1 Address: 0x80179AF4
 * EN v1.1 Size: 36b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80179af4(int param_1)
{
  char cVar1;
  
  cVar1 = *(char *)(*(int *)(param_1 + 0xb8) + 0x274);
  if ((cVar1 != '\x03') && (cVar1 != '\x02')) {
    return;
  }
  *(float *)(*(int *)(param_1 + 0xb8) + 0x26c) = FLOAT_803e4334;
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80179b18
 * EN v1.0 Address: TODO
 * EN v1.0 Size: TODO
 * EN v1.1 Address: 0x80179B18
 * EN v1.1 Size: 40b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_80179b18(int param_1)
{
  char cVar1;
  undefined4 uVar2;
  
  uVar2 = 0;
  cVar1 = *(char *)(*(int *)(param_1 + 0xb8) + 0x274);
  if ((cVar1 == '\x02') || (cVar1 == '\x01')) {
    uVar2 = 1;
  }
  return uVar2;
}

/*
 * --INFO--
 *
 * Function: FUN_80179b40
 * EN v1.0 Address: TODO
 * EN v1.0 Size: TODO
 * EN v1.1 Address: 0x80179B40
 * EN v1.1 Size: 68b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80179b40(int param_1)
{
  int iVar1;
  
  iVar1 = *(int *)(param_1 + 0xb8);
  *(float *)(iVar1 + 0x26c) = FLOAT_803e4334;
  *(undefined *)(iVar1 + 0x274) = 0;
  FUN_80035ff8(param_1);
  *(undefined *)(iVar1 + 0x25b) = 0;
  return;
}
