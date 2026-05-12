#include "ghidra_import.h"
#include "main/dll/dll_150.h"

extern undefined4 GameBit_Set(int eventId, int value);
extern uint FUN_80017730();
extern undefined4 FUN_80017748();
extern uint FUN_80017760();
extern void* FUN_80017aa4();
extern undefined4 FUN_80017ae4();
extern uint FUN_80017ae8();
extern undefined8 FUN_8028683c();
extern undefined4 FUN_80286888();
extern double FUN_80293900();
extern uint FUN_80294d50();
extern uint FUN_80294d58();

extern undefined4 DAT_803ad3f0;
extern undefined4 DAT_803ad3f4;
extern undefined4 DAT_803ad3f8;
extern f64 DOUBLE_803e4600;
extern f32 lbl_803E45C8;
extern f32 lbl_803E45D0;
extern f32 lbl_803E45D4;
extern f32 lbl_803E45D8;
extern f32 lbl_803E45DC;
extern f32 lbl_803E45E0;
extern f32 lbl_803E45E4;
extern f32 lbl_803E45E8;
extern f32 lbl_803E45EC;
extern f32 lbl_803E45F0;
extern f32 lbl_803E45F4;
extern f32 lbl_803E45F8;
extern f32 lbl_803E45FC;

/*
 * --INFO--
 *
 * Function: FUN_801816f8
 * EN v1.0 Address: 0x801816F8
 * EN v1.0 Size: 3228b
 * EN v1.1 Address: 0x80181C50
 * EN v1.1 Size: 2820b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801816f8(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined4 param_9,undefined4 param_10,int param_11,undefined4 param_12,
                 undefined4 param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16)
{
  float fVar1;
  uint uVar2;
  undefined2 *puVar3;
  short *psVar4;
  int iVar5;
  int iVar6;
  byte bVar7;
  bool bVar8;
  double dVar9;
  double in_f30;
  double dVar10;
  double in_f31;
  double in_ps30_1;
  double in_ps31_1;
  undefined8 uVar11;
  ushort local_68 [4];
  float local_60;
  float local_5c;
  float local_58;
  float local_54;
  undefined4 local_50;
  uint uStack_4c;
  undefined8 local_48;
  float local_18;
  float fStack_14;
  float local_8;
  float fStack_4;
  
  local_8 = (float)in_f31;
  fStack_4 = (float)in_ps31_1;
  local_18 = (float)in_f30;
  fStack_14 = (float)in_ps30_1;
  uVar11 = FUN_8028683c();
  iVar6 = (int)((ulonglong)uVar11 >> 0x20);
  iVar5 = (int)uVar11;
  if ((int)*(short *)(param_11 + 0x1c) != 0xffffffff) {
    GameBit_Set((int)*(short *)(param_11 + 0x1c),1);
  }
  uVar2 = FUN_80017ae8();
  if ((uVar2 & 0xff) != 0) {
    dVar9 = (double)DAT_803ad3f4;
    bVar8 = dVar9 < (double)lbl_803E45D4;
    bVar7 = *(byte *)(param_11 + 0x1e);
    if (bVar7 == 7) {
      uStack_4c = FUN_80294d58(iVar5);
      uStack_4c = uStack_4c ^ 0x80000000;
      local_50 = 0x43300000;
      dVar9 = (double)(float)((double)CONCAT44(0x43300000,uStack_4c) - DOUBLE_803e4600);
      uVar2 = FUN_80294d50(iVar5);
      local_48 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      dVar10 = (double)(float)(local_48 - DOUBLE_803e4600);
      param_2 = (double)((float)(dVar9 / dVar10) * lbl_803E45C8);
      dVar9 = (double)lbl_803E45D8;
      if (dVar9 < param_2) {
        if ((double)lbl_803E45DC < param_2) goto LAB_8018272c;
        local_48 = (double)(longlong)(int)(param_2 - dVar9);
        uVar2 = FUN_80017760(0,(int)(short)(int)(param_2 - dVar9));
        if ((int)uVar2 < 7) {
          bVar7 = 6;
          local_48 = (double)(longlong)(int)(dVar10 * (double)lbl_803E45D4);
          uVar2 = (uint)(short)(int)(dVar10 * (double)lbl_803E45D4);
          if ((int)uVar2 < 1) {
            uVar2 = 1;
          }
          FUN_80017760(1,uVar2);
        }
        else {
          bVar7 = 1;
          FUN_80017760(1,4);
        }
      }
      else {
        bVar7 = 6;
      }
    }
    if (bVar7 == 3) {
      puVar3 = FUN_80017aa4(0x24,0x3d5);
      uVar2 = FUN_80017760(0xffffff81,0x7e);
      *(char *)(puVar3 + 0xc) = (char)uVar2;
      *(undefined4 *)(puVar3 + 4) = *(undefined4 *)(iVar6 + 0xc);
      *(undefined4 *)(puVar3 + 6) = *(undefined4 *)(iVar6 + 0x10);
      *(undefined4 *)(puVar3 + 8) = *(undefined4 *)(iVar6 + 0x14);
      puVar3[0xd] = 2000;
      psVar4 = (short *)FUN_80017ae4(dVar9,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                                     puVar3,5,*(undefined *)(iVar6 + 0xac),0xffffffff,
                                     *(uint **)(iVar6 + 0x30),param_14,param_15,param_16);
      fVar1 = lbl_803E45E0;
      if (bVar8) {
        *(float *)(psVar4 + 0x12) = lbl_803E45E0 * DAT_803ad3f0;
        *(float *)(psVar4 + 0x14) = lbl_803E45E4 * DAT_803ad3f4;
        *(float *)(psVar4 + 0x16) = fVar1 * DAT_803ad3f8;
      }
      else {
        *(float *)(psVar4 + 0x12) = *(float *)(iVar6 + 0xc) - *(float *)(iVar5 + 0xc);
        *(float *)(psVar4 + 0x16) = *(float *)(iVar6 + 0x14) - *(float *)(iVar5 + 0x14);
      }
      dVar9 = (double)(*(float *)(psVar4 + 0x12) * *(float *)(psVar4 + 0x12) +
                      *(float *)(psVar4 + 0x16) * *(float *)(psVar4 + 0x16));
      if (dVar9 != (double)lbl_803E45D0) {
        dVar9 = FUN_80293900(dVar9);
        *(float *)(psVar4 + 0x12) = (float)((double)*(float *)(psVar4 + 0x12) / dVar9);
        *(float *)(psVar4 + 0x16) = (float)((double)*(float *)(psVar4 + 0x16) / dVar9);
      }
      uVar2 = FUN_80017760(0,0x19);
      local_48 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      *(float *)(psVar4 + 0x12) =
           *(float *)(psVar4 + 0x12) *
           -(lbl_803E45EC * (float)(local_48 - DOUBLE_803e4600) - lbl_803E45E8);
      uStack_4c = FUN_80017760(0,0x19);
      local_60 = lbl_803E45E8;
      uStack_4c = uStack_4c ^ 0x80000000;
      local_50 = 0x43300000;
      *(float *)(psVar4 + 0x16) =
           *(float *)(psVar4 + 0x16) *
           -(lbl_803E45EC * (float)((double)CONCAT44(0x43300000,uStack_4c) - DOUBLE_803e4600) -
            lbl_803E45E8);
      *(float *)(psVar4 + 0x14) = lbl_803E45F0;
      local_5c = lbl_803E45D0;
      local_58 = lbl_803E45D0;
      local_54 = lbl_803E45D0;
      local_68[2] = 0;
      local_68[1] = 0;
      uVar2 = FUN_80017760(0xffffd8f0,10000);
      local_68[0] = (ushort)uVar2;
      FUN_80017748(local_68,(float *)(psVar4 + 0x12));
      uVar2 = FUN_80017730();
      iVar6 = (int)*psVar4 - (uVar2 & 0xffff);
      if (0x8000 < iVar6) {
        iVar6 = iVar6 + -0xffff;
      }
      if (iVar6 < -0x8000) {
        iVar6 = iVar6 + 0xffff;
      }
      *psVar4 = (short)iVar6;
    }
    else if (bVar7 < 3) {
      if (bVar7 == 1) {
        puVar3 = FUN_80017aa4(0x24,0x3d3);
        *(undefined4 *)(puVar3 + 4) = *(undefined4 *)(iVar6 + 0xc);
        *(undefined4 *)(puVar3 + 6) = *(undefined4 *)(iVar6 + 0x10);
        *(undefined4 *)(puVar3 + 8) = *(undefined4 *)(iVar6 + 0x14);
        puVar3[0xd] = 400;
        psVar4 = (short *)FUN_80017ae4(dVar9,param_2,param_3,param_4,param_5,param_6,param_7,param_8
                                       ,puVar3,5,*(undefined *)(iVar6 + 0xac),0xffffffff,
                                       *(uint **)(iVar6 + 0x30),param_14,param_15,param_16);
        fVar1 = lbl_803E45E0;
        if (bVar8) {
          *(float *)(psVar4 + 0x12) = lbl_803E45E0 * DAT_803ad3f0;
          *(float *)(psVar4 + 0x14) = lbl_803E45E4 * DAT_803ad3f4;
          *(float *)(psVar4 + 0x16) = fVar1 * DAT_803ad3f8;
        }
        else {
          *(float *)(psVar4 + 0x12) = *(float *)(iVar6 + 0xc) - *(float *)(iVar5 + 0xc);
          *(float *)(psVar4 + 0x16) = *(float *)(iVar6 + 0x14) - *(float *)(iVar5 + 0x14);
        }
        dVar9 = (double)(*(float *)(psVar4 + 0x12) * *(float *)(psVar4 + 0x12) +
                        *(float *)(psVar4 + 0x16) * *(float *)(psVar4 + 0x16));
        if (dVar9 != (double)lbl_803E45D0) {
          dVar9 = FUN_80293900(dVar9);
          *(float *)(psVar4 + 0x12) = (float)((double)*(float *)(psVar4 + 0x12) / dVar9);
          *(float *)(psVar4 + 0x16) = (float)((double)*(float *)(psVar4 + 0x16) / dVar9);
        }
        uVar2 = FUN_80017760(0,0x19);
        local_48 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
        *(float *)(psVar4 + 0x12) =
             *(float *)(psVar4 + 0x12) *
             -(lbl_803E45EC * (float)(local_48 - DOUBLE_803e4600) - lbl_803E45E8);
        uStack_4c = FUN_80017760(0,0x19);
        local_60 = lbl_803E45E8;
        uStack_4c = uStack_4c ^ 0x80000000;
        local_50 = 0x43300000;
        *(float *)(psVar4 + 0x16) =
             *(float *)(psVar4 + 0x16) *
             -(lbl_803E45EC * (float)((double)CONCAT44(0x43300000,uStack_4c) - DOUBLE_803e4600) -
              lbl_803E45E8);
        *(float *)(psVar4 + 0x14) = lbl_803E45F0;
        local_5c = lbl_803E45D0;
        local_58 = lbl_803E45D0;
        local_54 = lbl_803E45D0;
        local_68[2] = 0;
        local_68[1] = 0;
        uVar2 = FUN_80017760(0xffffd8f0,10000);
        local_68[0] = (ushort)uVar2;
        FUN_80017748(local_68,(float *)(psVar4 + 0x12));
        uVar2 = FUN_80017730();
        iVar6 = (int)*psVar4 - (uVar2 & 0xffff);
        if (0x8000 < iVar6) {
          iVar6 = iVar6 + -0xffff;
        }
        if (iVar6 < -0x8000) {
          iVar6 = iVar6 + 0xffff;
        }
        *psVar4 = (short)iVar6;
      }
      else if (bVar7 != 0) {
        puVar3 = FUN_80017aa4(0x24,0x3d4);
        uVar2 = FUN_80017760(0xffffff81,0x7e);
        *(char *)(puVar3 + 0xc) = (char)uVar2;
        *(undefined4 *)(puVar3 + 4) = *(undefined4 *)(iVar6 + 0xc);
        *(undefined4 *)(puVar3 + 6) = *(undefined4 *)(iVar6 + 0x10);
        *(undefined4 *)(puVar3 + 8) = *(undefined4 *)(iVar6 + 0x14);
        puVar3[0xd] = 400;
        psVar4 = (short *)FUN_80017ae4(dVar9,param_2,param_3,param_4,param_5,param_6,param_7,param_8
                                       ,puVar3,5,*(undefined *)(iVar6 + 0xac),0xffffffff,
                                       *(uint **)(iVar6 + 0x30),param_14,param_15,param_16);
        fVar1 = lbl_803E45E0;
        if (bVar8) {
          *(float *)(psVar4 + 0x12) = lbl_803E45E0 * DAT_803ad3f0;
          *(float *)(psVar4 + 0x14) = lbl_803E45E4 * DAT_803ad3f4;
          *(float *)(psVar4 + 0x16) = fVar1 * DAT_803ad3f8;
        }
        else {
          *(float *)(psVar4 + 0x12) = *(float *)(iVar6 + 0xc) - *(float *)(iVar5 + 0xc);
          *(float *)(psVar4 + 0x16) = *(float *)(iVar6 + 0x14) - *(float *)(iVar5 + 0x14);
        }
        dVar9 = (double)(*(float *)(psVar4 + 0x12) * *(float *)(psVar4 + 0x12) +
                        *(float *)(psVar4 + 0x16) * *(float *)(psVar4 + 0x16));
        if (dVar9 != (double)lbl_803E45D0) {
          dVar9 = FUN_80293900(dVar9);
          *(float *)(psVar4 + 0x12) = (float)((double)*(float *)(psVar4 + 0x12) / dVar9);
          *(float *)(psVar4 + 0x16) = (float)((double)*(float *)(psVar4 + 0x16) / dVar9);
        }
        uVar2 = FUN_80017760(0,0x19);
        local_48 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
        *(float *)(psVar4 + 0x12) =
             *(float *)(psVar4 + 0x12) *
             -(lbl_803E45EC * (float)(local_48 - DOUBLE_803e4600) - lbl_803E45E8);
        uStack_4c = FUN_80017760(0,0x19);
        local_60 = lbl_803E45E8;
        uStack_4c = uStack_4c ^ 0x80000000;
        local_50 = 0x43300000;
        *(float *)(psVar4 + 0x16) =
             *(float *)(psVar4 + 0x16) *
             -(lbl_803E45EC * (float)((double)CONCAT44(0x43300000,uStack_4c) - DOUBLE_803e4600) -
              lbl_803E45E8);
        *(float *)(psVar4 + 0x14) = lbl_803E45F0;
        local_5c = lbl_803E45D0;
        local_58 = lbl_803E45D0;
        local_54 = lbl_803E45D0;
        local_68[2] = 0;
        local_68[1] = 0;
        uVar2 = FUN_80017760(0xffffd8f0,10000);
        local_68[0] = (ushort)uVar2;
        FUN_80017748(local_68,(float *)(psVar4 + 0x12));
        uVar2 = FUN_80017730();
        iVar6 = (int)*psVar4 - (uVar2 & 0xffff);
        if (0x8000 < iVar6) {
          iVar6 = iVar6 + -0xffff;
        }
        if (iVar6 < -0x8000) {
          iVar6 = iVar6 + 0xffff;
        }
        *psVar4 = (short)iVar6;
      }
    }
    else if ((bVar7 < 7) && (4 < bVar7)) {
      if (*(char *)(param_11 + 0x1e) == '\x05') {
        puVar3 = FUN_80017aa4(0x30,0xb);
      }
      else {
        puVar3 = FUN_80017aa4(0x30,0x3cd);
      }
      *(undefined *)(puVar3 + 0xd) = 0x14;
      puVar3[0x16] = 0xffff;
      puVar3[0xe] = 0xffff;
      if (*(char *)(param_11 + 9) == '\0') {
        *(undefined4 *)(puVar3 + 4) = *(undefined4 *)(iVar6 + 0xc);
        dVar9 = (double)lbl_803E45F8;
        *(float *)(puVar3 + 6) = (float)(dVar9 + (double)*(float *)(iVar6 + 0x10));
        *(undefined4 *)(puVar3 + 8) = *(undefined4 *)(iVar6 + 0x14);
      }
      else {
        uVar2 = FUN_80017760(0xfffffff1,0xf);
        local_48 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
        *(float *)(puVar3 + 4) = *(float *)(iVar6 + 0xc) + (float)(local_48 - DOUBLE_803e4600);
        *(float *)(puVar3 + 6) = lbl_803E45F4 + *(float *)(iVar6 + 0x10);
        uStack_4c = FUN_80017760(0xfffffff1,0xf);
        uStack_4c = uStack_4c ^ 0x80000000;
        local_50 = 0x43300000;
        dVar9 = (double)(float)((double)CONCAT44(0x43300000,uStack_4c) - DOUBLE_803e4600);
        *(float *)(puVar3 + 8) = (float)((double)*(float *)(iVar6 + 0x14) + dVar9);
      }
      puVar3[0x12] = 0xffff;
      psVar4 = (short *)FUN_80017ae4(dVar9,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                                     puVar3,5,*(undefined *)(iVar6 + 0xac),0xffffffff,
                                     *(uint **)(iVar6 + 0x30),param_14,param_15,param_16);
      fVar1 = lbl_803E45E0;
      if (bVar8) {
        *(float *)(psVar4 + 0x12) = lbl_803E45E0 * DAT_803ad3f0;
        *(float *)(psVar4 + 0x14) = lbl_803E45E4 * DAT_803ad3f4;
        *(float *)(psVar4 + 0x16) = fVar1 * DAT_803ad3f8;
      }
      dVar9 = (double)(*(float *)(psVar4 + 0x12) * *(float *)(psVar4 + 0x12) +
                      *(float *)(psVar4 + 0x16) * *(float *)(psVar4 + 0x16));
      if (dVar9 != (double)lbl_803E45D0) {
        dVar10 = FUN_80293900(dVar9);
        dVar9 = (double)lbl_803E45FC;
        *(float *)(psVar4 + 0x12) = *(float *)(psVar4 + 0x12) / (float)(dVar9 * dVar10);
        *(float *)(psVar4 + 0x16) = *(float *)(psVar4 + 0x16) / (float)(dVar9 * dVar10);
      }
      uVar2 = FUN_80017760(0,0x19);
      local_48 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      *(float *)(psVar4 + 0x12) =
           *(float *)(psVar4 + 0x12) *
           -(lbl_803E45EC * (float)(local_48 - DOUBLE_803e4600) - lbl_803E45E8);
      uStack_4c = FUN_80017760(0,0x19);
      uStack_4c = uStack_4c ^ 0x80000000;
      local_50 = 0x43300000;
      *(float *)(psVar4 + 0x16) =
           *(float *)(psVar4 + 0x16) *
           -(lbl_803E45EC * (float)((double)CONCAT44(0x43300000,uStack_4c) - DOUBLE_803e4600) -
            lbl_803E45E8);
      *(float *)(psVar4 + 0x14) = lbl_803E45F0;
      (**(code **)(**(int **)(psVar4 + 0x34) + 0x2c))
                ((double)*(float *)(psVar4 + 0x12),(double)*(float *)(psVar4 + 0x14),
                 (double)*(float *)(psVar4 + 0x16),psVar4);
      local_5c = lbl_803E45D0;
      local_58 = lbl_803E45D0;
      local_54 = lbl_803E45D0;
      local_60 = lbl_803E45E8;
      local_68[2] = 0;
      local_68[1] = 0;
      uVar2 = FUN_80017760(0xffffd8f0,10000);
      local_68[0] = (ushort)uVar2;
      FUN_80017748(local_68,(float *)(psVar4 + 0x12));
      uVar2 = FUN_80017730();
      iVar6 = (int)*psVar4 - (uVar2 & 0xffff);
      if (0x8000 < iVar6) {
        iVar6 = iVar6 + -0xffff;
      }
      if (iVar6 < -0x8000) {
        iVar6 = iVar6 + 0xffff;
      }
      *psVar4 = (short)iVar6;
    }
  }
LAB_8018272c:
  FUN_80286888();
  return;
}

/*
 * --INFO--
 *
 * Function: smallbasket_getExtraSize
 * EN v1.0 Address: 0x80182594
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x8018291C
 * EN v1.1 Size: 8b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int smallbasket_getExtraSize(void)
{
  return 0x24;
}
