#include "ghidra_import.h"
#include "main/dll/dll_138.h"

extern undefined4 FUN_80003494();
extern undefined4 FUN_80006824();
extern undefined4 FUN_80006b0c();
extern undefined4 FUN_80006b14();
extern uint FUN_80017690();
extern undefined4 FUN_80017698();
extern uint FUN_80017730();
extern undefined4 FUN_80017754();
extern uint FUN_80017760();
extern undefined4 FUN_80017778();
extern int FUN_80017a98();
extern undefined4 ObjGroup_FindNearestObject();
extern int FUN_80039520();
extern int FUN_800620e8();
extern undefined4 FUN_800e8630();
extern undefined4 FUN_801755cc();
extern undefined8 FUN_80286820();
extern undefined4 FUN_8028686c();
extern double FUN_80293900();
extern undefined4 FUN_80293f90();
extern undefined4 FUN_80294964();

extern undefined4* DAT_803dd6d0;
extern f64 DOUBLE_803e4210;
extern f32 lbl_803DC074;
extern f32 lbl_803E41C0;
extern f32 lbl_803E41D8;
extern f32 lbl_803E41DC;
extern f32 lbl_803E41E0;
extern f32 lbl_803E41E4;
extern f32 lbl_803E41E8;
extern f32 lbl_803E41EC;
extern f32 lbl_803E41F0;
extern f32 lbl_803E41F4;
extern f32 lbl_803E41F8;
extern f32 lbl_803E41FC;
extern f32 lbl_803E4200;
extern f32 lbl_803E4204;
extern f32 lbl_803E4208;
extern f32 lbl_803E4218;
extern f32 lbl_803E421C;
extern f32 lbl_803E4220;
extern f32 lbl_803E4230;

/*
 * --INFO--
 *
 * Function: FUN_80174a80
 * EN v1.0 Address: 0x80174A80
 * EN v1.0 Size: 1108b
 * EN v1.1 Address: 0x80174B14
 * EN v1.1 Size: 1048b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4
FUN_80174a80(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
            undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,uint param_9
            ,int param_10)
{
  float fVar1;
  float fVar2;
  float fVar3;
  bool bVar4;
  uint uVar5;
  undefined4 uVar6;
  int iVar7;
  int *piVar8;
  float local_38 [2];
  undefined8 local_30;
  undefined8 local_28;
  
  bVar4 = false;
  local_38[0] = lbl_803E41D8;
  FUN_801755cc(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9);
  uVar5 = FUN_80017690((int)*(short *)(param_10 + 0xac));
  fVar2 = lbl_803E41DC;
  if (uVar5 == 0) {
    if (*(int *)(param_10 + 0xbc) == 0) {
      uVar6 = ObjGroup_FindNearestObject(0x11,param_9,local_38);
      *(undefined4 *)(param_10 + 0xbc) = uVar6;
    }
    if (*(int *)(param_10 + 0xbc) == 0) {
      uVar6 = 0;
    }
    else {
      if (*(float *)(param_10 + 0xd8) < lbl_803E41E8) {
        *(float *)(param_10 + 0xd8) = lbl_803E41E8;
      }
      fVar2 = *(float *)(*(int *)(param_10 + 0xbc) + 0x14) - *(float *)(param_9 + 0x14);
      if (fVar2 < lbl_803E41C0) {
        fVar2 = fVar2 * lbl_803E41EC;
      }
      fVar1 = *(float *)(param_10 + 0xf0);
      if (lbl_803E41F0 + fVar2 <= fVar1) {
        fVar3 = *(float *)(*(int *)(param_10 + 0xbc) + 0xc) - *(float *)(param_9 + 0xc);
        if (fVar3 < lbl_803E41C0) {
          fVar3 = fVar3 * lbl_803E41EC;
        }
        if (fVar3 <= lbl_803E41F4) {
          if ((lbl_803E41F0 + fVar2 <= fVar1) && (fVar1 <= lbl_803E41F8 + fVar2)) {
            bVar4 = true;
            FUN_80017698(0x1c9,1);
          }
          iVar7 = FUN_80039520(param_9,0);
          *(float *)(param_10 + 0xec) =
               *(float *)(param_10 + 0xe8) * lbl_803DC074 + *(float *)(param_10 + 0xec);
          if (*(float *)(param_10 + 0xec) < *(float *)(param_10 + 0xe4)) {
            if (*(float *)(param_10 + 0xec) < lbl_803E41C0) {
              uVar5 = FUN_80017760(0x19,0x4b);
              local_30 = (double)CONCAT44(0x43300000,uVar5 ^ 0x80000000);
              *(float *)(param_10 + 0xe4) = lbl_803E41FC * (float)(local_30 - DOUBLE_803e4210);
              uVar5 = FUN_80017760(0x28,0x46);
              local_28 = (double)CONCAT44(0x43300000,uVar5 ^ 0x80000000);
              *(float *)(param_10 + 0xe8) =
                   *(float *)(param_10 + 0xe4) / (float)(local_28 - DOUBLE_803e4210);
              *(float *)(param_10 + 0xec) = lbl_803E41C0;
            }
          }
          else {
            *(float *)(param_10 + 0xe8) = *(float *)(param_10 + 0xe8) * lbl_803E41EC;
          }
          if (iVar7 != 0) {
            *(float *)(param_10 + 0xd8) = *(float *)(param_10 + 0xd8) + *(float *)(param_10 + 0xcc);
            if (*(float *)(param_10 + 0xd8) < lbl_803E4200) {
              *(float *)(param_10 + 0xdc) =
                   *(float *)(param_10 + 0xdc) + *(float *)(param_10 + 0xd0);
              if (*(float *)(param_10 + 0xdc) <= lbl_803E4204) {
                if (*(float *)(param_10 + 0xdc) < lbl_803E41C0) {
                  *(float *)(param_10 + 0xdc) = lbl_803E4204;
                }
              }
              else {
                *(float *)(param_10 + 0xdc) = lbl_803E4204;
              }
              *(float *)(param_10 + 0xe0) =
                   *(float *)(param_10 + 0xe0) + *(float *)(param_10 + 0xd4);
              if (*(float *)(param_10 + 0xe0) <= lbl_803E4204) {
                if (*(float *)(param_10 + 0xe0) < lbl_803E41C0) {
                  *(float *)(param_10 + 0xe0) = lbl_803E4204;
                }
              }
              else {
                *(float *)(param_10 + 0xe0) = lbl_803E4204;
              }
              fVar2 = *(float *)(param_10 + 0xdc);
              fVar3 = lbl_803E4208 + *(float *)(param_10 + 0xec);
              fVar1 = *(float *)(param_10 + 0xe0);
              *(char *)(iVar7 + 0xc) = (char)(int)*(float *)(param_10 + 0xd8);
              *(char *)(iVar7 + 0xd) = (char)(int)(fVar2 * fVar3);
              *(char *)(iVar7 + 0xe) = (char)(int)(fVar1 * fVar3);
            }
            else {
              FUN_80017698((int)*(short *)(param_10 + 0xac),1);
              if (bVar4) {
                FUN_80017698(0x1c9,0);
              }
              piVar8 = (int *)FUN_80006b14(0x5b);
              (**(code **)(*piVar8 + 4))(param_9,0x14,0,2,0xffffffff,0);
              (**(code **)(*piVar8 + 4))(param_9,0x14,0,2,0xffffffff,0);
              FUN_80006b0c((undefined *)piVar8);
              FUN_80006824(param_9,0x65);
            }
          }
          uVar6 = 0;
        }
        else {
          uVar6 = 0;
        }
      }
      else {
        uVar6 = 0;
      }
    }
  }
  else {
    if (lbl_803E41DC < *(float *)(param_9 + 8)) {
      *(float *)(param_9 + 8) = -(lbl_803E41E0 * lbl_803DC074 - *(float *)(param_9 + 8));
      if (*(float *)(param_9 + 8) <= fVar2) {
        *(float *)(param_9 + 8) = lbl_803E41C0;
        *(float *)(param_9 + 0x10) = *(float *)(param_9 + 0x10) - lbl_803E41E4;
        *(byte *)(param_9 + 0xaf) = *(byte *)(param_9 + 0xaf) | 8;
      }
    }
    uVar6 = 1;
  }
  return uVar6;
}

/*
 * --INFO--
 *
 * Function: FUN_80174ed4
 * EN v1.0 Address: 0x80174ED4
 * EN v1.0 Size: 376b
 * EN v1.1 Address: 0x80174F2C
 * EN v1.1 Size: 380b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80174ed4(int param_1,int param_2)
{
  float fVar1;
  uint uVar2;
  int iVar3;
  
  iVar3 = *(int *)(param_1 + 0x4c);
  *(float *)(param_2 + 0xcc) = lbl_803E4218;
  fVar1 = lbl_803E421C;
  *(float *)(param_2 + 0xd0) = lbl_803E421C;
  *(float *)(param_2 + 0xd4) = fVar1;
  uVar2 = FUN_80017760(0x19,0x4b);
  *(float *)(param_2 + 0xe4) =
       lbl_803E41FC * (float)((double)CONCAT44(0x43300000,uVar2 ^ 0x80000000) - DOUBLE_803e4210);
  uVar2 = FUN_80017760(0x28,0x46);
  *(float *)(param_2 + 0xe8) =
       *(float *)(param_2 + 0xe4) /
       (float)((double)CONCAT44(0x43300000,uVar2 ^ 0x80000000) - DOUBLE_803e4210);
  fVar1 = lbl_803E41C0;
  *(float *)(param_2 + 0xec) = lbl_803E41C0;
  *(undefined2 *)(param_2 + 0xac) = *(undefined2 *)(iVar3 + 0x18);
  *(undefined2 *)(param_2 + 0xae) = *(undefined2 *)(iVar3 + 0x1a);
  *(float *)(param_2 + 0xf0) = fVar1;
  *(undefined4 *)(param_2 + 0xbc) = 0;
  FUN_80017698((int)*(short *)(param_2 + 0xac),0);
  iVar3 = FUN_80039520(param_1,0);
  *(float *)(param_2 + 0xdc) = *(float *)(param_2 + 0xdc) + *(float *)(param_2 + 0xd0);
  if (*(float *)(param_2 + 0xdc) <= lbl_803E4204) {
    if (*(float *)(param_2 + 0xdc) < lbl_803E41C0) {
      *(float *)(param_2 + 0xdc) = lbl_803E4204;
    }
  }
  else {
    *(float *)(param_2 + 0xdc) = lbl_803E4204;
  }
  *(float *)(param_2 + 0xe0) = *(float *)(param_2 + 0xe0) + *(float *)(param_2 + 0xd4);
  if (*(float *)(param_2 + 0xe0) <= lbl_803E4204) {
    if (*(float *)(param_2 + 0xe0) < lbl_803E41C0) {
      *(float *)(param_2 + 0xe0) = lbl_803E4204;
    }
  }
  else {
    *(float *)(param_2 + 0xe0) = lbl_803E4204;
  }
  *(undefined *)(iVar3 + 0xc) = 10;
  *(undefined *)(iVar3 + 0xd) = 10;
  *(undefined *)(iVar3 + 0xe) = 10;
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8017504c
 * EN v1.0 Address: 0x8017504C
 * EN v1.0 Size: 1052b
 * EN v1.1 Address: 0x801750A8
 * EN v1.1 Size: 1296b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8017504c(void)
{
  ushort uVar1;
  byte bVar2;
  ushort *puVar3;
  int iVar4;
  uint uVar5;
  undefined4 *puVar6;
  int iVar7;
  int iVar8;
  int iVar9;
  int iVar10;
  int iVar11;
  int iVar12;
  int iVar13;
  float *pfVar14;
  float *pfVar15;
  double in_f28;
  double dVar16;
  double in_f29;
  double dVar17;
  double in_f30;
  double dVar18;
  double in_f31;
  double dVar19;
  double in_ps28_1;
  double in_ps29_1;
  double in_ps30_1;
  double in_ps31_1;
  undefined8 uVar20;
  ushort local_190;
  ushort local_18e;
  ushort local_18c;
  float local_188;
  int local_184;
  int local_180;
  int local_17c;
  float afStack_178 [12];
  float local_148;
  float local_144;
  float local_140;
  int aiStack_138 [20];
  char local_e7;
  float local_e4 [21];
  undefined4 local_90;
  uint uStack_8c;
  undefined4 local_88;
  uint uStack_84;
  float local_38;
  float fStack_34;
  float local_28;
  float fStack_24;
  float local_18;
  float fStack_14;
  float local_8;
  float fStack_4;
  
  local_8 = (float)in_f31;
  fStack_4 = (float)in_ps31_1;
  local_18 = (float)in_f30;
  fStack_14 = (float)in_ps30_1;
  local_28 = (float)in_f29;
  fStack_24 = (float)in_ps29_1;
  local_38 = (float)in_f28;
  fStack_34 = (float)in_ps28_1;
  uVar20 = FUN_80286820();
  puVar3 = (ushort *)((ulonglong)uVar20 >> 0x20);
  iVar7 = (int)uVar20;
  iVar12 = *(int *)(puVar3 + 0x26);
  FUN_80017a98();
  dVar18 = (double)*(float *)(puVar3 + 6);
  dVar17 = (double)*(float *)(puVar3 + 8);
  dVar16 = (double)*(float *)(puVar3 + 10);
  bVar2 = 0xf;
  iVar10 = 0;
  dVar19 = (double)lbl_803E4220;
  do {
    if (bVar2 == 0) {
LAB_80175568:
      FUN_80003494(iVar7 + 0x78,(uint)local_e4,*(char *)(iVar7 + 0xb4) * 0xc);
      FUN_8028686c();
      return;
    }
    bVar2 = 0xf;
    iVar10 = iVar10 + 1;
    if (4 < iVar10) {
      *(float *)(puVar3 + 6) = (float)dVar18;
      *(float *)(puVar3 + 8) = (float)dVar17;
      *(float *)(puVar3 + 10) = (float)dVar16;
      goto LAB_80175568;
    }
    iVar9 = 8;
    iVar8 = 4;
    pfVar15 = local_e4;
    iVar13 = iVar7;
    pfVar14 = (float *)(iVar7 + 0x18);
    for (iVar11 = 0; iVar11 < *(char *)(iVar7 + 0xb4); iVar11 = iVar11 + 1) {
      local_190 = *puVar3;
      local_18e = puVar3[1];
      local_18c = puVar3[2];
      local_188 = (float)dVar19;
      local_184 = *(int *)(puVar3 + 6);
      local_180 = *(int *)(puVar3 + 8);
      local_17c = *(int *)(puVar3 + 10);
      FUN_80017754(afStack_178,&local_190);
      FUN_80017778((double)*pfVar14,(double)pfVar14[1],(double)pfVar14[2],afStack_178,pfVar15,
                   (float *)((int)local_e4 + iVar8),(float *)((int)local_e4 + iVar9));
      if ((1 << iVar11 & 0xfU) != 0) {
        iVar4 = FUN_800620e8(iVar13 + 0x78,pfVar15,(float *)0x1,aiStack_138,(int *)puVar3,8,0xd,
                             iVar11 + 3U & 0xff,10);
        if (iVar4 == 0) {
          bVar2 = bVar2 & ~(byte)(1 << iVar11);
        }
        else {
          if ((local_e7 != -1) && ((*(ushort *)(iVar7 + 0x100) & 1) == 0)) {
            *(ushort *)(iVar7 + 0x100) = *(ushort *)(iVar7 + 0x100) | 1;
            uVar5 = (uint)*(short *)(iVar12 + 0x18);
            if (-1 < (int)uVar5) {
              uVar1 = puVar3[0x23];
              if (uVar1 != 0x411) {
                if ((short)uVar1 < 0x411) {
                  if (uVar1 != 0x21e) {
                    if ((0x21d < (short)uVar1) || (uVar1 != 0x1cb)) goto LAB_8017533c;
                    if (local_e7 == '\x01') {
                      FUN_80017698(uVar5,1);
                      FUN_80006824(0,0x109);
                      *(ushort *)(iVar7 + 0x100) = *(ushort *)(iVar7 + 0x100) | 0x80;
                      *(byte *)((int)puVar3 + 0xaf) = *(byte *)((int)puVar3 + 0xaf) | 8;
                      FUN_800e8630((int)puVar3);
                    }
                  }
                }
                else if (uVar1 == 0x7df) {
                  *(ushort *)(iVar7 + 0x100) = *(ushort *)(iVar7 + 0x100) & 0xfffe;
                  if ((int)local_e7 == (uint)*(byte *)(iVar7 + 0x144)) {
                    puVar6 = (undefined4 *)FUN_80039520((int)puVar3,0);
                    if (puVar6 != (undefined4 *)0x0) {
                      *puVar6 = 0x100;
                    }
                    FUN_80017698((int)*(short *)(iVar12 + 0x18),1);
                    *(byte *)((int)puVar3 + 0xaf) = *(byte *)((int)puVar3 + 0xaf) | 8;
                    *(ushort *)(iVar7 + 0x100) = *(ushort *)(iVar7 + 0x100) | 0x80;
                  }
                }
                else {
LAB_8017533c:
                  if ((-1 < *(char *)(iVar12 + 0x23)) && (*(char *)(iVar12 + 0x23) == local_e7)) {
                    FUN_80017698(uVar5,1);
                    FUN_80006824(0,0x109);
                  }
                }
              }
            }
          }
          uStack_8c = *(uint *)(iVar7 + 0x140) ^ 0x80000000;
          local_90 = 0x43300000;
          FUN_80293f90();
          uStack_84 = *(uint *)(iVar7 + 0x140) ^ 0x80000000;
          local_88 = 0x43300000;
          FUN_80294964();
          uVar5 = FUN_80017730();
          iVar4 = *(int *)(iVar7 + 0x140) - (uVar5 & 0xffff);
          if (0x8000 < iVar4) {
            iVar4 = iVar4 + -0xffff;
          }
          if (iVar4 < -0x8000) {
            iVar4 = iVar4 + 0xffff;
          }
          iVar4 = iVar4 / 0xb6 + (iVar4 >> 0x1f);
          iVar4 = iVar4 - (iVar4 >> 0x1f);
          if ((iVar4 < -0x1d) || (0x1d < iVar4)) {
            if ((iVar4 < 0x97) && (-0x97 < iVar4)) {
              if ((iVar4 < 0x3d) || (0x77 < iVar4)) {
                if ((iVar4 < -0x3c) && (-0x78 < iVar4)) {
                  *(ushort *)(iVar7 + 0x100) = *(ushort *)(iVar7 + 0x100) | 0x400;
                  *(float *)(iVar7 + 0x10c) = lbl_803E41C0;
                }
              }
              else {
                *(ushort *)(iVar7 + 0x100) = *(ushort *)(iVar7 + 0x100) | 0x800;
                *(float *)(iVar7 + 0x10c) = lbl_803E41C0;
              }
            }
            else {
              *(ushort *)(iVar7 + 0x100) = *(ushort *)(iVar7 + 0x100) | 0x200;
              *(float *)(iVar7 + 0x108) = lbl_803E41C0;
            }
          }
          else {
            *(ushort *)(iVar7 + 0x100) = *(ushort *)(iVar7 + 0x100) | 0x100;
            *(float *)(iVar7 + 0x108) = lbl_803E41C0;
          }
          FUN_80003494(iVar13 + 0x78,(uint)pfVar15,0xc);
          local_148 = *pfVar15;
          local_144 = pfVar15[1];
          local_140 = pfVar15[2];
          FUN_80017778(-(double)*pfVar14,-(double)pfVar14[1],-(double)pfVar14[2],afStack_178,
                       (float *)(puVar3 + 6),(float *)(puVar3 + 8),(float *)(puVar3 + 10));
        }
      }
      iVar9 = iVar9 + 0xc;
      iVar8 = iVar8 + 0xc;
      pfVar15 = pfVar15 + 3;
      pfVar14 = pfVar14 + 3;
      iVar13 = iVar13 + 0xc;
    }
  } while( true );
}

/*
 * --INFO--
 *
 * Function: FUN_80175468
 * EN v1.0 Address: 0x80175468
 * EN v1.0 Size: 744b
 * EN v1.1 Address: 0x801755B8
 * EN v1.1 Size: 796b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_80175468(short *param_1,short *param_2,int param_3)
{
  uint uVar1;
  int iVar2;
  int iVar3;
  double dVar4;
  double dVar5;
  double dVar6;
  
  iVar3 = *(int *)(param_1 + 0x5c);
  *(undefined *)(iVar3 + 0x145) = 0x3c;
  if (param_1[0x5a] != -1) {
    (**(code **)(*DAT_803dd6d0 + 0x4c))();
  }
  *(undefined2 *)(param_3 + 0x70) = 0xffff;
  if (*(char *)(param_3 + 0x56) != '\0') {
    if (*(char *)(param_3 + 0x56) != '\x02') {
      *(float *)(param_3 + 0x4c) = lbl_803E4220;
      *(float *)(param_3 + 0x40) = *(float *)(param_1 + 6) - *(float *)(param_2 + 6);
      *(float *)(param_3 + 0x44) = *(float *)(param_1 + 8) - *(float *)(param_2 + 8);
      *(float *)(param_3 + 0x48) = *(float *)(param_1 + 10) - *(float *)(param_2 + 10);
      *(short *)(param_3 + 0x50) = *param_1 - *param_2;
      if (0x8000 < *(short *)(param_3 + 0x50)) {
        *(short *)(param_3 + 0x50) = *(short *)(param_3 + 0x50) + 1;
      }
      if (*(short *)(param_3 + 0x50) < -0x8000) {
        *(short *)(param_3 + 0x50) = *(short *)(param_3 + 0x50) + -1;
      }
      *(short *)(param_3 + 0x52) = param_1[1] - param_2[1];
      if (0x8000 < *(short *)(param_3 + 0x52)) {
        *(short *)(param_3 + 0x52) = *(short *)(param_3 + 0x52) + 1;
      }
      if (*(short *)(param_3 + 0x52) < -0x8000) {
        *(short *)(param_3 + 0x52) = *(short *)(param_3 + 0x52) + -1;
      }
      *(short *)(param_3 + 0x54) = param_2[2] - param_1[2];
      if (0x8000 < *(short *)(param_3 + 0x54)) {
        *(short *)(param_3 + 0x54) = *(short *)(param_3 + 0x54) + 1;
      }
      if (*(short *)(param_3 + 0x54) < -0x8000) {
        *(short *)(param_3 + 0x54) = *(short *)(param_3 + 0x54) + -1;
      }
      *(undefined *)(param_3 + 0x56) = 2;
    }
    *(float *)(param_3 + 0x4c) =
         -(*(float *)(param_3 + 0x24) * lbl_803DC074 - *(float *)(param_3 + 0x4c));
    if (*(float *)(param_3 + 0x4c) <= lbl_803E41C0) {
      *(undefined *)(param_3 + 0x56) = 0;
    }
  }
  if (*(int *)(param_1 + 0x7c) == 0) {
    param_1[0x7c] = 0;
    param_1[0x7d] = 2;
  }
  if ((param_1[0x23] == 0x21e) || (param_1[0x23] == 0x411)) {
    *(byte *)((int)param_1 + 0xaf) = *(byte *)((int)param_1 + 0xaf) | 8;
    if (('\0' < *(char *)(*(int *)(param_1 + 0x2c) + 0x10f)) &&
       ((*(short *)(*(int *)(*(int *)(param_1 + 0x2c) + 0x100) + 0x44) == 0x24 &&
        (uVar1 = FUN_80017690(0x103), uVar1 == 0)))) {
      FUN_80017698(0x103,1);
      *(byte *)((int)param_1 + 0xaf) = *(byte *)((int)param_1 + 0xaf) & 0xf7;
      iVar2 = FUN_80017a98();
      dVar6 = (double)(*(float *)(param_1 + 6) - *(float *)(iVar2 + 0xc));
      dVar5 = (double)(*(float *)(param_1 + 10) - *(float *)(iVar2 + 0x14));
      dVar4 = FUN_80293900((double)(float)(dVar6 * dVar6 + (double)(float)(dVar5 * dVar5)));
      if (dVar4 != (double)lbl_803E41C0) {
        dVar6 = (double)(float)(dVar6 / dVar4);
        dVar5 = (double)(float)(dVar5 / dVar4);
      }
      dVar4 = (double)lbl_803E4230;
      *(float *)(iVar3 + 0xc0) = (float)(dVar4 * dVar6);
      *(float *)(iVar3 + 0xc4) = lbl_803E41C0;
      *(float *)(iVar3 + 200) = (float)(dVar4 * dVar5);
      return 4;
    }
  }
  return 0;
}

/*
 * --INFO--
 *
 * Function: pushable_render2
 * EN v1.0 Address: 0x80175520
 * EN v1.0 Size: 16b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int pushable_render2(int obj)
{
  return *(ushort *)(*(int *)(obj + 0xb8) + 0x100) & 1;
}

/*
 * --INFO--
 *
 * Function: pushable_modelMtxFn
 * EN v1.0 Address: 0x80175530
 * EN v1.0 Size: 28b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
void pushable_modelMtxFn(int obj,int modelNo)
{
  int extra = *(int *)(obj + 0xb8);
  uint flags = *(uint *)(extra + 0xa8);

  *(uint *)(extra + 0xa8) = flags | (1 << modelNo);
}
#pragma scheduling reset
