#include "ghidra_import.h"
#include "main/dll/VF/VFlevcontrol.h"

extern undefined4 FUN_8000a538();
extern undefined4 FUN_8000bb38();
extern uint FUN_80020078();
extern undefined4 FUN_800201ac();
extern uint FUN_80022264();
extern undefined4 FUN_8002bac4();
extern undefined4 FUN_80035ff8();
extern undefined4 FUN_80036018();
extern undefined4 FUN_8011f670();
extern undefined4 FUN_8011f9b8();
extern undefined4 FUN_801de018();
extern undefined4 FUN_80286838();
extern int FUN_8028683c();
extern undefined4 FUN_80286884();
extern undefined4 FUN_80286888();
extern undefined4 FUN_80296884();

extern undefined4 DAT_803286b0;
extern undefined4* DAT_803dd6cc;
extern undefined4* DAT_803dd6d0;
extern undefined4* DAT_803dd6e8;
extern undefined4* DAT_803dd72c;
extern f64 DOUBLE_803e62e0;
extern f32 FLOAT_803dc074;
extern f32 FLOAT_803e62d0;
extern f32 FLOAT_803e62d4;
extern f32 FLOAT_803e62ec;
extern f32 FLOAT_803e62f0;
extern f32 FLOAT_803e62f4;
extern f32 FLOAT_803e62f8;

/*
 * --INFO--
 *
 * Function: FUN_801de458
 * EN v1.0 Address: 0x801DE458
 * EN v1.0 Size: 1208b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801de458(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)
{
  int iVar1;
  ushort uVar2;
  bool bVar3;
  float fVar4;
  ushort *puVar5;
  undefined2 *puVar6;
  uint uVar7;
  uint uVar8;
  byte bVar9;
  uint uVar10;
  short *psVar11;
  byte local_38 [8];
  undefined4 local_30;
  uint uStack_2c;
  longlong local_28;
  
  puVar5 = (ushort *)FUN_80286838();
  psVar11 = *(short **)(puVar5 + 0x5c);
  puVar6 = (undefined2 *)FUN_8002bac4();
  if ((*(byte *)(psVar11 + 0x13) & 1) != 0) {
    psVar11[0x10] = 0;
    psVar11[0x11] = 1;
    *puVar5 = 0x3fff;
    uVar2 = *puVar5;
    psVar11[0x12] = ((short)uVar2 >> 0xd) + (ushort)((short)uVar2 < 0 && (uVar2 & 0x1fff) != 0);
    FUN_80035ff8((int)puVar5);
    FUN_801de018((double)FLOAT_803e62d0,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
    FUN_800201ac((uint)*(ushort *)(psVar11[0x12] * 2 + -0x7fcd7960),1);
    *(undefined *)(puVar5 + 0x1b) = 0;
    *(byte *)(psVar11 + 0x13) = *(byte *)(psVar11 + 0x13) & 0xfe;
    *(byte *)(psVar11 + 0x13) = *(byte *)(psVar11 + 0x13) | 2;
    (**(code **)(*DAT_803dd6e8 + 0x40))(1);
    FUN_8011f670(1);
    (**(code **)(*DAT_803dd6cc + 0xc))(0x1e,1);
    *(float *)(psVar11 + 0xc) = FLOAT_803e62d4;
    FUN_8000a538((int *)0xf0,1);
  }
  fVar4 = FLOAT_803e62ec;
  if ((*(byte *)(psVar11 + 0x13) & 2) != 0) {
    if (*(float *)(psVar11 + 0xc) == FLOAT_803e62ec) {
      if (*(float *)(psVar11 + 0xe) == FLOAT_803e62ec) {
        uVar7 = FUN_80020078(0x64c);
        if (uVar7 != 0) {
          FUN_800201ac(0x64c,0);
          uVar7 = 0;
          for (bVar9 = 0; bVar9 < 8; bVar9 = bVar9 + 1) {
            uVar8 = FUN_80020078((uint)(ushort)(&DAT_803286b0)[bVar9]);
            uVar10 = uVar7;
            if (uVar8 == 0) {
              uVar10 = uVar7 + 1;
              local_38[uVar7 & 0xff] = bVar9;
            }
            uVar7 = uVar10;
          }
          if ((uVar7 & 0xff) == 0) {
            bVar3 = true;
          }
          else {
            uVar7 = FUN_80022264(0,(uVar7 & 0xff) - 1);
            bVar9 = local_38[uVar7];
            if ((int)psVar11[0x12] == (uint)bVar9) {
              FUN_800201ac((uint)*(ushort *)(psVar11[0x12] * 2 + -0x7fcd7960),1);
            }
            if ((int)psVar11[0x12] != (uint)bVar9) {
              psVar11[0x12] = (ushort)bVar9;
              FUN_8000bb38((uint)puVar5,0x137);
            }
            bVar3 = false;
          }
          if (bVar3) {
            *(float *)(psVar11 + 0xe) = FLOAT_803e62f0;
            FUN_8011f9b8(0);
            (**(code **)(*DAT_803dd6cc + 8))(0x1e,1);
          }
        }
        if ((uint)(*puVar5 >> 0xd) != (int)psVar11[0x12]) {
          uStack_2c = (int)(short)*puVar5 ^ 0x80000000;
          local_30 = 0x43300000;
          iVar1 = (int)-(FLOAT_803e62f4 * FLOAT_803dc074 -
                        (float)((double)CONCAT44(0x43300000,uStack_2c) - DOUBLE_803e62e0));
          local_28 = (longlong)iVar1;
          *puVar5 = (ushort)iVar1;
          if ((uint)(*puVar5 >> 0xd) == (int)psVar11[0x12]) {
            FUN_800201ac((uint)*(ushort *)(psVar11[0x12] * 2 + -0x7fcd7960),1);
          }
        }
      }
      else {
        *(float *)(psVar11 + 0xe) = *(float *)(psVar11 + 0xe) - FLOAT_803dc074;
        if (*(float *)(psVar11 + 0xe) <= fVar4) {
          *(float *)(psVar11 + 0xe) = fVar4;
          puVar6 = (undefined2 *)FUN_8002bac4();
          (**(code **)(*DAT_803dd72c + 0x2c))();
          (**(code **)(*DAT_803dd6d0 + 0x1c))(0x42,0,3,0,0,0,0);
          *(undefined *)(puVar5 + 0x1b) = 0xff;
          FUN_80296884(puVar6,(undefined4 *)0x0,(undefined2 *)0x0);
          FUN_80036018((int)puVar5);
          FUN_8011f670(0);
          FUN_800201ac(700,1);
          *(undefined *)(psVar11 + 0x13) = 0;
          FUN_8000a538((int *)0xf0,0);
          goto LAB_801de8b4;
        }
      }
    }
    else {
      *(float *)(psVar11 + 0xc) = *(float *)(psVar11 + 0xc) - FLOAT_803dc074;
      if (*(float *)(psVar11 + 0xc) < fVar4) {
        *(float *)(psVar11 + 0xc) = fVar4;
      }
    }
    FUN_80296884(puVar6,(undefined4 *)(puVar5 + 6),puVar5);
    *(undefined4 *)(psVar11 + 4) = *(undefined4 *)(puVar5 + 6);
    *(float *)(psVar11 + 6) = FLOAT_803e62d4 + *(float *)(puVar5 + 8);
    *(undefined4 *)(psVar11 + 8) = *(undefined4 *)(puVar5 + 10);
    *psVar11 = -0x8000 - *puVar5;
    psVar11[1] = puVar5[1];
    psVar11[2] = puVar5[2];
    *(float *)(psVar11 + 10) = FLOAT_803e62f8;
    (**(code **)(*DAT_803dd6d0 + 0x60))(psVar11,0x18);
  }
  if ((*(byte *)(psVar11 + 0x13) & 0x10) != 0) {
    (**(code **)(*DAT_803dd72c + 0x44))(0xe,6);
    *(byte *)(psVar11 + 0x13) = *(byte *)(psVar11 + 0x13) & 0xef;
  }
LAB_801de8b4:
  FUN_80286884();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801de910
 * EN v1.0 Address: 0x801DE910
 * EN v1.0 Size: 272b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801de910(void)
{
  ushort uVar1;
  ushort uVar2;
  int iVar3;
  uint uVar4;
  undefined2 extraout_r4;
  byte bVar5;
  byte bVar6;
  ushort local_28 [20];
  
  iVar3 = FUN_8028683c();
  for (bVar6 = 0; bVar6 < 3; bVar6 = bVar6 + 1) {
    uVar4 = FUN_80020078((uint)*(ushort *)(iVar3 + (uint)bVar6 * 2));
    local_28[bVar6] = (ushort)uVar4;
  }
  local_28[3] = extraout_r4;
  for (bVar6 = 0; bVar6 < 3; bVar6 = bVar6 + 1) {
    for (bVar5 = 0; bVar5 < 3; bVar5 = bVar5 + 1) {
      uVar1 = local_28[bVar5 + 1];
      if (uVar1 != 0) {
        uVar2 = local_28[bVar5];
        if ((uVar1 < uVar2) || (uVar2 == 0)) {
          local_28[bVar5] = uVar1;
          local_28[bVar5 + 1] = uVar2;
        }
      }
    }
  }
  for (bVar6 = 0; bVar6 < 3; bVar6 = bVar6 + 1) {
    FUN_800201ac((uint)*(ushort *)(iVar3 + (uint)bVar6 * 2),(uint)local_28[bVar6]);
  }
  FUN_80286888();
  return;
}
