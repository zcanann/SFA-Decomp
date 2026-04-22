#include "ghidra_import.h"
#include "main/dll/dll_D1.h"

extern bool FUN_8000b598();
extern undefined4 FUN_8000bb38();
extern undefined4 FUN_8000dbb0();
extern undefined4 FUN_8000dcdc();
extern int FUN_80021884();
extern uint FUN_80022264();
extern void* FUN_8002becc();
extern undefined4 FUN_8002e088();
extern uint FUN_8002e144();
extern undefined4 FUN_800394f0();
extern undefined4 FUN_80139cb8();
extern undefined4 FUN_8013a778();
extern int FUN_8013b6f0();
extern undefined4 FUN_80148ff0();
extern undefined4 FUN_801784f8();
extern undefined8 FUN_8028683c();
extern undefined4 FUN_80286888();

extern f32 FLOAT_803e306c;
extern f32 FLOAT_803e30d4;
extern f32 FLOAT_803e3158;
extern f32 FLOAT_803e315c;
extern f32 FLOAT_803e3160;

/*
 * --INFO--
 *
 * Function: FUN_8013e010
 * EN v1.0 Address: 0x8013E010
 * EN v1.0 Size: 1096b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8013e010(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined4 param_9,undefined4 param_10,int param_11,undefined4 param_12,
                 byte param_13,uint param_14,undefined4 param_15,undefined4 param_16)
{
  byte bVar1;
  float fVar2;
  ushort *puVar3;
  int iVar4;
  uint uVar5;
  bool bVar8;
  undefined2 *puVar6;
  undefined4 uVar7;
  undefined4 *puVar9;
  undefined4 *puVar10;
  undefined8 extraout_f1;
  undefined8 extraout_f1_00;
  undefined8 uVar11;
  
  uVar11 = FUN_8028683c();
  puVar3 = (ushort *)((ulonglong)uVar11 >> 0x20);
  puVar9 = (undefined4 *)uVar11;
  bVar1 = *(byte *)((int)puVar9 + 10);
  if (bVar1 == 2) {
    FUN_80148ff0();
    iVar4 = FUN_8013b6f0((double)FLOAT_803e315c,param_2,param_3,param_4,param_5,param_6,param_7,
                         param_8,puVar3,puVar9,param_11,param_12,param_13,param_14,param_15,param_16
                        );
    if (iVar4 == 0) {
      uVar11 = extraout_f1;
      uVar5 = FUN_8002e144();
      if ((uVar5 & 0xff) != 0) {
        puVar9[0x15] = puVar9[0x15] | 0x800;
        iVar4 = 0;
        puVar10 = puVar9;
        do {
          puVar6 = FUN_8002becc(0x24,0x4f0);
          *(undefined *)(puVar6 + 2) = 2;
          *(undefined *)((int)puVar6 + 5) = 1;
          puVar6[0xd] = (short)iVar4;
          uVar7 = FUN_8002e088(uVar11,param_2,param_3,param_4,param_5,param_6,param_7,param_8,puVar6
                               ,5,*(undefined *)(puVar3 + 0x56),0xffffffff,*(uint **)(puVar3 + 0x18)
                               ,param_14,param_15,param_16);
          puVar10[0x1c0] = uVar7;
          puVar10 = puVar10 + 1;
          iVar4 = iVar4 + 1;
          uVar11 = extraout_f1_00;
        } while (iVar4 < 7);
        FUN_8000bb38((uint)puVar3,0x3db);
        FUN_8000dcdc((uint)puVar3,0x3dc);
      }
      *(char *)*puVar9 = *(char *)*puVar9 + -1;
      FUN_8013a778((double)FLOAT_803e30d4,(int)puVar3,0x34,0x4000000);
      puVar9[0x15] = puVar9[0x15] | 0x10;
      *(undefined *)((int)puVar9 + 10) = 3;
      puVar9[0x1ca] = 0;
    }
  }
  else if (bVar1 < 2) {
    if (bVar1 == 0) {
      FUN_80148ff0();
      iVar4 = FUN_8013b6f0((double)FLOAT_803e3158,param_2,param_3,param_4,param_5,param_6,param_7,
                           param_8,puVar3,puVar9,param_11,param_12,param_13,param_14,param_15,
                           param_16);
      if (iVar4 == 0) {
        iVar4 = *(int *)(puVar3 + 0x5c);
        if ((((*(byte *)(iVar4 + 0x58) >> 6 & 1) == 0) &&
            ((0x2f < (short)puVar3[0x50] || ((short)puVar3[0x50] < 0x29)))) &&
           (bVar8 = FUN_8000b598((int)puVar3,0x10), !bVar8)) {
          FUN_800394f0(puVar3,iVar4 + 0x3a8,0x299,0x100,0xffffffff,0);
        }
        *(undefined *)((int)puVar9 + 10) = 1;
        FUN_8013a778((double)FLOAT_803e30d4,(int)puVar3,0x33,0x4000000);
        puVar9[0x1ca] = 0;
      }
    }
    else {
      FUN_80148ff0();
      if ((*(char *)*puVar9 == '\0') || (puVar9[0x1ca] == 0)) {
        iVar4 = FUN_80021884();
        FUN_80139cb8(puVar3,(ushort)iVar4);
        uVar5 = FUN_80022264(0,10);
        if (((uVar5 == 0) &&
            (iVar4 = *(int *)(puVar3 + 0x5c), (*(byte *)(iVar4 + 0x58) >> 6 & 1) == 0)) &&
           (((0x2f < (short)puVar3[0x50] || ((short)puVar3[0x50] < 0x29)) &&
            (bVar8 = FUN_8000b598((int)puVar3,0x10), !bVar8)))) {
          FUN_800394f0(puVar3,iVar4 + 0x3a8,0x299,0x100,0xffffffff,0);
        }
      }
      else {
        *(undefined *)((int)puVar9 + 10) = 2;
      }
    }
  }
  else if (bVar1 < 4) {
    FUN_80148ff0();
    if (*(float *)(puVar3 + 0x4c) < FLOAT_803e3160) {
      iVar4 = FUN_80021884();
      FUN_80139cb8(puVar3,(ushort)iVar4);
    }
    else {
      puVar9[0x15] = puVar9[0x15] & 0xfffff7ff;
      puVar9[0x15] = puVar9[0x15] | 0x1000;
      iVar4 = 0;
      puVar10 = puVar9;
      do {
        FUN_801784f8(puVar10[0x1c0]);
        puVar10 = puVar10 + 1;
        iVar4 = iVar4 + 1;
      } while (iVar4 < 7);
      FUN_8000dbb0();
      iVar4 = *(int *)(puVar3 + 0x5c);
      if (((*(byte *)(iVar4 + 0x58) >> 6 & 1) == 0) &&
         (((0x2f < (short)puVar3[0x50] || ((short)puVar3[0x50] < 0x29)) &&
          (bVar8 = FUN_8000b598((int)puVar3,0x10), !bVar8)))) {
        FUN_800394f0(puVar3,iVar4 + 0x3a8,0x29d,0,0xffffffff,0);
      }
      *(undefined *)(puVar9 + 2) = 1;
      *(undefined *)((int)puVar9 + 10) = 0;
      fVar2 = FLOAT_803e306c;
      puVar9[0x1c7] = FLOAT_803e306c;
      puVar9[0x1c8] = fVar2;
      puVar9[0x15] = puVar9[0x15] & 0xffffffef;
      puVar9[0x15] = puVar9[0x15] & 0xfffeffff;
      puVar9[0x15] = puVar9[0x15] & 0xfffdffff;
      puVar9[0x15] = puVar9[0x15] & 0xfffbffff;
      *(undefined *)((int)puVar9 + 0xd) = 0xff;
    }
  }
  FUN_80286888();
  return;
}
