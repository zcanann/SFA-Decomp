#include "ghidra_import.h"
#include "main/dll/gfxEmit.h"

#define SFXwp_whiz3_c 0x169

extern undefined4 FUN_80006824();
extern uint FUN_80017690();
extern undefined8 FUN_80017698();
extern undefined4 FUN_80017710();
extern u32 randomGetRange(int min, int max);
extern undefined4 FUN_80017a88();
extern int FUN_80017a98();
extern undefined8 ObjGroup_RemoveObject();
extern undefined4 ObjMsg_SendToObject();
extern int ObjTrigger_IsSet();
extern undefined4 FUN_8003b56c();
extern undefined4 FUN_8003b818();
extern undefined4 FUN_800810f4();
extern undefined4 FUN_80081118();
extern undefined4 FUN_801713ac();
extern int FUN_80286840();
extern undefined4 FUN_8028688c();
extern double FUN_80293900();
extern undefined4 FUN_80293f90();
extern undefined4 FUN_80294964();
extern uint FUN_80294c78();
extern int FUN_80294dbc();
extern uint countLeadingZeros();

extern undefined4 DAT_803dc070;
extern undefined4* DAT_803dd6f8;
extern undefined4* DAT_803dd708;
extern undefined4* DAT_803dd728;
extern int *gExpgfxInterface;
extern f64 DOUBLE_803e40e0;
extern f64 DOUBLE_803e4108;
extern f32 lbl_803DC074;
extern f32 lbl_803E40EC;
extern f32 lbl_803E40F0;
extern f32 lbl_803E40F4;
extern f32 lbl_803E40F8;
extern f32 lbl_803E40FC;
extern f32 lbl_803E4100;
extern f32 lbl_803E4104;
extern f32 lbl_803E4110;
extern f32 lbl_803E4114;
extern f32 lbl_803E4118;
extern f32 lbl_803E411C;
extern f32 lbl_803E4124;
extern f32 lbl_803E4128;

/*
 * --INFO--
 *
 * Function: FUN_801723dc
 * EN v1.0 Address: 0x801723DC
 * EN v1.0 Size: 720b
 * EN v1.1 Address: 0x801725F0
 * EN v1.1 Size: 664b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801723dc(int param_1)
{
  float fVar1;
  float fVar2;
  uint uVar3;
  int iVar4;
  double dVar5;
  double dVar6;
  double dVar7;
  double dVar8;
  double dVar9;
  
  iVar4 = *(int *)(param_1 + 0xb8);
  if (*(short *)(param_1 + 0x46) == 0x6a6) {
    FUN_80017a88((double)lbl_803E40F4,
                 (double)(*(float *)(param_1 + 0x28) *
                         (float)((double)CONCAT44(0x43300000,(uint)DAT_803dc070) - DOUBLE_803e4108))
                 ,(double)lbl_803E40F4,param_1);
  }
  else {
    uVar3 = (uint)DAT_803dc070;
    FUN_80017a88((double)(*(float *)(param_1 + 0x24) *
                         (float)((double)CONCAT44(0x43300000,uVar3) - DOUBLE_803e4108)),
                 (double)(*(float *)(param_1 + 0x28) *
                         (float)((double)CONCAT44(0x43300000,uVar3) - DOUBLE_803e4108)),
                 (double)(*(float *)(param_1 + 0x2c) *
                         (float)((double)CONCAT44(0x43300000,uVar3) - DOUBLE_803e4108)),param_1);
  }
  (**(code **)(*DAT_803dd728 + 0x10))((double)lbl_803DC074,param_1,iVar4 + 0x50);
  (**(code **)(*DAT_803dd728 + 0x14))(param_1,iVar4 + 0x50);
  (**(code **)(*DAT_803dd728 + 0x18))((double)lbl_803DC074,param_1,iVar4 + 0x50);
  if (*(char *)(iVar4 + 0x2b1) == '\0') {
    *(float *)(param_1 + 0x28) = *(float *)(param_1 + 0x28) * lbl_803E4100;
    *(float *)(param_1 + 0x28) = -(lbl_803E4104 * lbl_803DC074 - *(float *)(param_1 + 0x28));
  }
  else {
    dVar8 = -(double)*(float *)(param_1 + 0x24);
    dVar7 = -(double)*(float *)(param_1 + 0x28);
    dVar9 = -(double)*(float *)(param_1 + 0x2c);
    dVar6 = FUN_80293900((double)(float)(dVar9 * dVar9 +
                                        (double)(float)(dVar8 * dVar8 +
                                                       (double)(float)(dVar7 * dVar7))));
    if ((double)lbl_803E40F4 != dVar6) {
      dVar5 = (double)(float)((double)lbl_803E40EC / dVar6);
      dVar8 = (double)(float)(dVar8 * dVar5);
      dVar7 = (double)(float)(dVar7 * dVar5);
      dVar9 = (double)(float)(dVar9 * dVar5);
    }
    fVar1 = *(float *)(iVar4 + 0xbc);
    fVar2 = *(float *)(iVar4 + 0xc0);
    dVar5 = (double)(lbl_803E40F8 *
                    (float)(dVar9 * (double)fVar2 +
                           (double)(float)(dVar8 * (double)*(float *)(iVar4 + 0xb8) +
                                          (double)(float)(dVar7 * (double)fVar1))));
    *(float *)(param_1 + 0x24) = (float)((double)*(float *)(iVar4 + 0xb8) * dVar5);
    *(float *)(param_1 + 0x28) = (float)((double)fVar1 * dVar5);
    *(float *)(param_1 + 0x2c) = (float)((double)fVar2 * dVar5);
    *(float *)(param_1 + 0x24) = (float)((double)*(float *)(param_1 + 0x24) - dVar8);
    *(float *)(param_1 + 0x28) = (float)((double)*(float *)(param_1 + 0x28) - dVar7);
    *(float *)(param_1 + 0x2c) = (float)((double)*(float *)(param_1 + 0x2c) - dVar9);
    *(float *)(param_1 + 0x28) = (float)((double)*(float *)(param_1 + 0x28) * dVar6);
    *(float *)(param_1 + 0x28) = *(float *)(param_1 + 0x28) * lbl_803E40FC;
    *(float *)(param_1 + 0x24) = (float)((double)*(float *)(param_1 + 0x24) * dVar6);
    *(float *)(param_1 + 0x2c) = (float)((double)*(float *)(param_1 + 0x2c) * dVar6);
    *(char *)(iVar4 + 0x1d) = *(char *)(iVar4 + 0x1d) + -1;
    if (*(char *)(iVar4 + 0x1d) == '\0') {
      *(undefined *)(iVar4 + 0x1d) = 0;
      fVar1 = lbl_803E40F4;
      *(float *)(param_1 + 0x24) = lbl_803E40F4;
      *(float *)(param_1 + 0x28) = fVar1;
      *(float *)(param_1 + 0x2c) = fVar1;
    }
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801726ac
 * EN v1.0 Address: 0x801726AC
 * EN v1.0 Size: 712b
 * EN v1.1 Address: 0x80172888
 * EN v1.1 Size: 676b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801726ac(short *param_1)
{
  short sVar1;
  ushort uVar2;
  uint uVar3;
  float *pfVar4;
  undefined8 local_18;
  undefined8 local_10;
  
  pfVar4 = *(float **)(param_1 + 0x5c);
  sVar1 = param_1[0x23];
  if (sVar1 != 0x137) {
    if (sVar1 < 0x137) {
      if (sVar1 != 0x12d) {
        if (sVar1 < 0x12d) {
          if (sVar1 == 0x22) {
            local_10 = (double)CONCAT44(0x43300000,(int)*param_1 ^ 0x80000000);
            *param_1 = (short)(int)(lbl_803E4114 * lbl_803DC074 +
                                   (float)(local_10 - DOUBLE_803e40e0));
            FUN_80081118((double)lbl_803E40EC,param_1,10,1);
            return;
          }
          if (0x21 < sVar1) {
            return;
          }
          if (sVar1 != 0xb) {
            return;
          }
          sVar1 = *(short *)(pfVar4 + 0xd);
          uVar2 = (ushort)DAT_803dc070;
          *(ushort *)(pfVar4 + 0xd) = sVar1 - uVar2;
          if ((short)(sVar1 - uVar2) < 1) {
            uVar3 = randomGetRange(600,800);
            local_18 = (double)CONCAT44(0x43300000,uVar3 ^ 0x80000000);
            pfVar4[0xc] = (float)(local_18 - DOUBLE_803e40e0);
            uVar3 = randomGetRange(0xb4,0xf0);
            *(short *)(pfVar4 + 0xd) = (short)uVar3;
            FUN_80006824((uint)param_1,SFXwp_whiz3_c);
          }
          param_1[1] = (short)(int)pfVar4[0xc];
          pfVar4[0xc] = pfVar4[0xc] * lbl_803E4110;
          if (9 < param_1[1]) {
            return;
          }
          if (param_1[1] < -9) {
            return;
          }
          param_1[1] = 0;
          return;
        }
        if (sVar1 != 0x135) {
          return;
        }
      }
    }
    else {
      if (sVar1 == 0x27f) {
        if (lbl_803E4114 <= *pfVar4) {
          return;
        }
        uVar3 = randomGetRange(0,10);
        if (uVar3 == 0) {
          (**(code **)(*DAT_803dd708 + 8))(param_1,0x423,0,2,0xffffffff,0);
        }
        *param_1 = *param_1 + (short)(int)(lbl_803E4118 * lbl_803DC074);
        return;
      }
      if (0x27e < sVar1) {
        if (sVar1 != 0x5e8) {
          return;
        }
        local_10 = (double)CONCAT44(0x43300000,(int)*param_1 ^ 0x80000000);
        *param_1 = (short)(int)(lbl_803E4114 * lbl_803DC074 +
                               (float)(local_10 - DOUBLE_803e40e0));
        FUN_80081118((double)lbl_803E40EC,param_1,9,1);
        return;
      }
      if (sVar1 != 0x246) {
        if (0x245 < sVar1) {
          return;
        }
        if (sVar1 != 0x156) {
          return;
        }
      }
    }
  }
  local_18 = (double)CONCAT44(0x43300000,(int)*param_1 ^ 0x80000000);
  *param_1 = (short)(int)(lbl_803E4114 * lbl_803DC074 + (float)(local_18 - DOUBLE_803e40e0));
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80172974
 * EN v1.0 Address: 0x80172974
 * EN v1.0 Size: 460b
 * EN v1.1 Address: 0x80172B2C
 * EN v1.1 Size: 420b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80172974(undefined4 param_1,undefined4 param_2,int param_3)
{
  char cVar1;
  float fVar2;
  int iVar3;
  uint uVar4;
  int iVar5;
  int iVar6;
  int iVar7;
  double dVar8;
  double dVar9;
  double in_f31;
  double dVar10;
  double in_ps31_1;
  undefined auStack_48 [12];
  float local_3c;
  float local_38;
  float local_34;
  float local_8;
  float fStack_4;
  
  local_8 = (float)in_f31;
  fStack_4 = (float)in_ps31_1;
  iVar3 = FUN_80286840();
  iVar7 = *(int *)(iVar3 + 0xb8);
  if ((int)*(short *)(iVar7 + 0x14) != 0xffffffff) {
    uVar4 = FUN_80017690((int)*(short *)(iVar7 + 0x14));
    uVar4 = countLeadingZeros(uVar4);
    *(char *)(iVar7 + 0x1e) = (char)(uVar4 >> 5);
  }
  if ((*(char *)(iVar7 + 0x1e) == '\0') && (*(short *)(iVar3 + 0x46) == 0x6a6)) {
    FUN_800810f4((double)lbl_803E40EC,(double)lbl_803E40F0,iVar3,5,6,1,0x14,0,0);
  }
  *(undefined *)(param_3 + 0x56) = 0;
  for (iVar5 = 0; iVar5 < (int)(uint)*(byte *)(param_3 + 0x8b); iVar5 = iVar5 + 1) {
    cVar1 = *(char *)(param_3 + iVar5 + 0x81);
    if (cVar1 == '\x01') {
      dVar8 = (double)FUN_80294964();
      dVar10 = (double)(float)((double)lbl_803E411C * dVar8);
      dVar9 = (double)FUN_80293f90();
      dVar8 = (double)lbl_803E411C;
      *(undefined *)(*(int *)(iVar3 + 0xb8) + 0x1d) = 8;
      *(float *)(iVar3 + 0x24) = (float)(dVar8 * dVar9);
      fVar2 = lbl_803E40F8;
      *(float *)(iVar3 + 0x28) = lbl_803E40F8;
      *(float *)(iVar3 + 0x2c) = (float)dVar10;
      *(undefined *)(*(int *)(iVar3 + 0xb8) + 0x1d) = 8;
      *(float *)(iVar3 + 0x24) = lbl_803E4124;
      *(float *)(iVar3 + 0x28) = fVar2;
      *(float *)(iVar3 + 0x2c) = lbl_803E40F4;
    }
    else if (cVar1 == '\x02') {
      *(undefined *)(iVar7 + 0x3e) = 1;
    }
    else if (cVar1 == '\x03') {
      iVar6 = 0;
      dVar8 = (double)lbl_803E40F4;
      do {
        local_3c = (float)dVar8;
        local_38 = (float)dVar8;
        local_34 = (float)dVar8;
        (**(code **)(*DAT_803dd708 + 8))(iVar3,0x7ef,auStack_48,1,0xffffffff,0);
        iVar6 = iVar6 + 1;
      } while (iVar6 < 10);
    }
  }
  FUN_8028688c();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80172b40
 * EN v1.0 Address: 0x80172B40
 * EN v1.0 Size: 1280b
 * EN v1.1 Address: 0x80172CD0
 * EN v1.1 Size: 688b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80172b40(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)
{
  short sVar1;
  uint uVar2;
  int iVar3;
  int iVar4;
  uint uVar5;
  float *pfVar6;
  undefined4 in_r7;
  undefined4 in_r8;
  undefined4 in_r9;
  undefined4 in_r10;
  int iVar7;
  double dVar8;
  double dVar9;
  undefined8 uVar10;
  
  uVar10 = FUN_80286840();
  uVar2 = (uint)((ulonglong)uVar10 >> 0x20);
  pfVar6 = (float *)uVar10;
  iVar7 = *(int *)(uVar2 + 0x4c);
  iVar3 = FUN_80017a98();
  if ((iVar3 == 0) || ((*(byte *)((int)pfVar6 + 0x37) & 1) != 0)) goto LAB_80172f50;
  iVar4 = FUN_80294dbc(iVar3);
  if (iVar4 == 0) {
    iVar4 = iVar3;
  }
  dVar8 = (double)FUN_80017710((float *)(uVar2 + 0x18),(float *)(iVar4 + 0x18));
  dVar9 = (double)(*(float *)(iVar4 + 0x1c) - *(float *)(uVar2 + 0x1c));
  if (dVar9 < (double)lbl_803E40F4) {
    dVar9 = -dVar9;
  }
  if (((dVar9 < (double)lbl_803E4128) && (dVar8 < (double)pfVar6[1])) &&
     (uVar5 = FUN_80294c78(iVar3), uVar5 != 0)) {
    *(undefined2 *)(pfVar6 + 0x12) = 0xffff;
    sVar1 = *(short *)(uVar2 + 0x46);
    if (sVar1 == 0x319) {
      FUN_801713ac(dVar9,param_2,param_3,param_4,param_5,param_6,param_7,param_8,uVar2);
      *(byte *)((int)pfVar6 + 0x37) = *(byte *)((int)pfVar6 + 0x37) | 1;
    }
    else if (sVar1 < 0x319) {
      if (sVar1 == 0x49) {
LAB_80172e44:
        uVar5 = FUN_80017690(0x90f);
        if (uVar5 == 0) {
          ObjMsg_SendToObject(dVar9,param_2,param_3,param_4,param_5,param_6,param_7,param_8,iVar3,0x7000a,
                       uVar2,(uint)(pfVar6 + 0x12),in_r7,in_r8,in_r9,in_r10);
          FUN_80017698(0x90f,1);
        }
        else {
          FUN_801713ac(dVar9,param_2,param_3,param_4,param_5,param_6,param_7,param_8,uVar2);
        }
        *(byte *)((int)pfVar6 + 0x37) = *(byte *)((int)pfVar6 + 0x37) | 1;
      }
      else {
        if (sVar1 < 0x49) {
          if (sVar1 == 0xb) {
            uVar5 = FUN_80017690(0x90e);
            if (uVar5 == 0) {
              ObjMsg_SendToObject(dVar9,param_2,param_3,param_4,param_5,param_6,param_7,param_8,iVar3,
                           0x7000a,uVar2,(uint)(pfVar6 + 0x12),in_r7,in_r8,in_r9,in_r10);
              FUN_80017698(0x90e,1);
            }
            else {
              FUN_801713ac(dVar9,param_2,param_3,param_4,param_5,param_6,param_7,param_8,uVar2);
            }
            *(byte *)((int)pfVar6 + 0x37) = *(byte *)((int)pfVar6 + 0x37) | 1;
            goto LAB_80172f4c;
          }
        }
        else if (sVar1 == 0x2da) goto LAB_80172e44;
LAB_80172eec:
        iVar4 = ObjTrigger_IsSet(uVar2);
        if (iVar4 != 0) {
          uVar10 = FUN_80017698(0xa7b,1);
          *(undefined2 *)(pfVar6 + 0x12) = *(undefined2 *)(iVar7 + 0x1e);
          ObjMsg_SendToObject(uVar10,param_2,param_3,param_4,param_5,param_6,param_7,param_8,iVar3,0x7000a,
                       uVar2,(uint)(pfVar6 + 0x12),in_r7,in_r8,in_r9,in_r10);
          *(byte *)((int)pfVar6 + 0x37) = *(byte *)((int)pfVar6 + 0x37) | 1;
          if (*(int *)(uVar2 + 100) != 0) {
            *(undefined4 *)(*(int *)(uVar2 + 100) + 0x30) = 0x1000;
          }
        }
      }
    }
    else {
      if (sVar1 != 0x6a6) {
        if ((0x6a5 < sVar1) || (sVar1 != 0x3cd)) goto LAB_80172eec;
        goto LAB_80172e44;
      }
      uVar5 = FUN_80017690(0x9a8);
      if (uVar5 == 0) {
        ObjMsg_SendToObject(dVar9,param_2,param_3,param_4,param_5,param_6,param_7,param_8,iVar3,0x7000a,
                     uVar2,(uint)(pfVar6 + 0x12),in_r7,in_r8,in_r9,in_r10);
        FUN_80017698(0x9a8,1);
      }
      else {
        FUN_801713ac(dVar9,param_2,param_3,param_4,param_5,param_6,param_7,param_8,uVar2);
      }
      *(byte *)((int)pfVar6 + 0x37) = *(byte *)((int)pfVar6 + 0x37) | 1;
    }
  }
LAB_80172f4c:
  *pfVar6 = (float)dVar8;
LAB_80172f50:
  FUN_8028688c();
  return;
}

/*
 * --INFO--
 *
 * Function: collectible_free
 * EN v1.0 Address: 0x80173040
 * EN v1.0 Size: 76b
 * EN v1.1 Address: 0x80172F80
 * EN v1.1 Size: 72b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void collectible_free(int obj)
{
  (*(void (*)(int))(*(int *)(*gExpgfxInterface + 0x18)))(obj);
  ObjGroup_RemoveObject(obj,4);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8017308c
 * EN v1.0 Address: 0x8017308C
 * EN v1.0 Size: 216b
 * EN v1.1 Address: 0x80172FC8
 * EN v1.1 Size: 260b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8017308c(int param_1,int param_2,int param_3,int param_4,int param_5,s8 visible)
{
  int iVar1;
  int iVar2;
  
  iVar1 = FUN_80286840();
  iVar2 = *(int *)(iVar1 + 0xb8);
  if ((((visible != 0) && (*(float *)(iVar2 + 8) == lbl_803E40F4)) &&
      (*(int *)(iVar1 + 0xf4) == 0)) &&
     ((*(short *)(iVar1 + 0x46) == 0x156 || (*(char *)(iVar2 + 0x1e) == '\0')))) {
    if (((*(uint *)(*(int *)(iVar1 + 0x50) + 0x44) & 0x10000) != 0) &&
       (*(char *)(iVar2 + 0x36) != '\0')) {
      FUN_8003b56c((ushort)*(byte *)(iVar2 + 0x38),(ushort)*(byte *)(iVar2 + 0x39),
                   (ushort)*(byte *)(iVar2 + 0x3a));
    }
    FUN_8003b818(iVar1);
    if (*(short *)(iVar1 + 0x46) == 0xa8) {
      FUN_800810f4((double)lbl_803E40EC,(double)lbl_803E4124,iVar1,7,5,1,10,0,0x20000000);
    }
  }
  FUN_8028688c();
  return;
}

/*
 * --INFO--
 *
 * Function: collectible_getExtraSize
 * EN v1.0 Address: 0x80172E34
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x80172D70
 * EN v1.1 Size: 8b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int collectible_getExtraSize(void)
{
  return 0x2b8;
}

/*
 * --INFO--
 *
 * Function: collectible_getObjectTypeId
 * EN v1.0 Address: 0x80172E3C
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x80172D78
 * EN v1.1 Size: 8b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int collectible_getObjectTypeId(void)
{
  return 0x13;
}

/*
 * --INFO--
 *
 * Function: collectible_hitDetect
 * EN v1.0 Address: 0x80172F90
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80172ECC
 * EN v1.1 Size: 4b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void collectible_hitDetect(void)
{
}

extern uint GameBit_Get(int);
extern f32 sin(f32 x);
extern f32 fn_80293E80(f32 x);
extern void objfx_spawnDirectionalBurst(int obj, int a, f32 fa, int b, int c, int d, f32 fb, int e, int f);
extern int* gPartfxInterface;
extern f32 lbl_803E3454;
extern f32 lbl_803E3458;
extern f32 lbl_803E345C;
extern f32 lbl_803E3460;
extern f32 lbl_803E3484;
extern f32 lbl_803E3488;
extern f32 lbl_803E348C;

#pragma scheduling off
#pragma peephole off
int collectible_SeqFn(int obj, int unused, u8* data)
{
    int* state = *(int**)(obj + 0xb8);
    f32 buf[6];
    int i;
    int j;
    f32 s_val;
    f32 c_val;

    if (*(s16*)((char*)state + 0x14) != -1) {
        *(u8*)((char*)state + 0x1e) = (u8)(GameBit_Get((s32)*(s16*)((char*)state + 0x14)) == 0);
    }
    if (*(u8*)((char*)state + 0x1e) == 0) {
        if (*(s16*)(obj + 0x46) == 0x6a6) {
            objfx_spawnDirectionalBurst(obj, 5, lbl_803E3454, 6, 1, 0x14, lbl_803E3458, 0, 0);
        }
    }

    data[0x56] = 0;
    for (i = 0; i < (s32)data[0x8b]; i++) {
        u8 cmd = data[0x81 + i];
        if (cmd == 1) {
            s_val = lbl_803E3484 * sin(lbl_803E3488);
            c_val = lbl_803E3484 * fn_80293E80(lbl_803E3488);
            *(u8*)((char*)*(int**)(obj + 0xb8) + 0x1d) = 8;
            *(f32*)(obj + 0x24) = c_val;
            *(f32*)(obj + 0x28) = lbl_803E3460;
            *(f32*)(obj + 0x2c) = s_val;
            *(u8*)((char*)*(int**)(obj + 0xb8) + 0x1d) = 8;
            *(f32*)(obj + 0x24) = lbl_803E348C;
            *(f32*)(obj + 0x28) = lbl_803E3460;
            *(f32*)(obj + 0x2c) = lbl_803E345C;
        } else if (cmd == 2) {
            *(u8*)((char*)state + 0x3e) = 1;
        } else if (cmd == 3) {
            for (j = 0; j < 10; j++) {
                buf[3] = lbl_803E345C;
                buf[4] = lbl_803E345C;
                buf[5] = lbl_803E345C;
                (*(void(**)(int, int, f32*, int, int, int))(*gPartfxInterface + 0x8))(obj, 0x7ef, buf, 1, -1, 0);
            }
        }
    }
    return 0;
}
#pragma peephole reset
#pragma scheduling reset

extern void fn_80171E5C(int obj);
extern void fn_80172144(int obj);
extern int  ObjMsg_Pop(int obj, int *msg, void *buf, int mode);
extern void ObjHits_DisableObject(int obj);
extern void Obj_FreeObject(int obj);
extern u8  *Obj_GetPlayerObject(void);
extern void GameBit_Set(int eventId, int value);
extern void Sfx_PlayFromObject(int obj, int sfxId);
extern void itemPickupDoParticleFx(int obj, int a, int b, f32 scale);
extern int  fn_802972A8(void);
extern int  fn_8029622C(int player);
extern f32  Vec_xzDistance(void *a, void *b);
extern void fn_8003B608(int r, int g, int b);
extern void objRenderFn_8003b8f4(f32 e, int obj, int p2, int p3, int p4, int p5);
extern int *gPartfxInterface;
extern f32  timeDelta;
extern u8   framesThisStep;
extern f32  lbl_803E3450;
extern f32  lbl_803E3478;
extern f32  lbl_803E347C;
extern f32  lbl_803E3480;
extern f32  lbl_803E348C;
extern f32  lbl_803E3490;
void fn_801723DC(int obj);
void fn_80172824(int obj, u8 *st);

/* EN v1.0 0x80172C24  size: 752b  collectible_update. */
#pragma scheduling off
#pragma peephole off
void collectible_update(int obj)
{
    u8 *st = *(u8 **)(obj + 0xb8);
    int msg;
    int msgId;
    u8 buf[8];
    int o;

    *(u8 *)(obj + 0xaf) = (u8)(*(u8 *)(obj + 0xaf) | 8);
    if (*(f32 *)(st + 8) != lbl_803E345C) {
        *(f32 *)(st + 8) = *(f32 *)(st + 8) - timeDelta;
        if (*(f32 *)(st + 8) <= lbl_803E345C) {
            *(f32 *)(st + 8) = lbl_803E345C;
            ObjHits_DisableObject(obj);
            if ((*(s16 *)(obj + 6) & 0x2000U) != 0) {
                Obj_FreeObject(obj);
            }
        }
    } else {
        if (*(s16 *)(st + 0x14) != -1) {
            st[0x1e] = (u8)(GameBit_Get(*(s16 *)(st + 0x14)) == 0);
        }
        if (st[0x1e] == 0 && st[0xf] == 0) {
            if (*(s16 *)(obj + 0x46) == 0x6a6) {
                objfx_spawnDirectionalBurst(obj, 5, lbl_803E3454, 6, 1, 0x14, lbl_803E3458, 0, 0);
            }
            if (*(f32 *)(st + 0x44) == lbl_803E345C ||
                (*(f32 *)(st + 0x44) = *(f32 *)(st + 0x44) - timeDelta,
                 !(*(f32 *)(st + 0x44) <= lbl_803E345C))) {
                msgId = 0x7000b;
                while (ObjMsg_Pop(obj, &msg, buf, 0) != 0) {
                    if (msg == msgId) {
                        fn_80171E5C(obj);
                    }
                }
                if (*(s16 *)(obj + 0x46) == 0x319 && *(s16 *)(st + 0x3c) != 0 &&
                    (*(u16 *)(st + 0x3c) = *(s16 *)(st + 0x3c) - framesThisStep,
                     *(s16 *)(st + 0x3c) < 1)) {
                    *(u16 *)(st + 0x3c) = 0;
                    st[0x37] = (u8)(st[0x37] & ~1);
                    *(u8 *)(obj + 0x36) = 0xff;
                    *(int *)(obj + 0xf4) = 0;
                }
                if (*(int *)(obj + 0xf4) == 0) {
                    *(u8 *)(obj + 0xaf) = (u8)(*(u8 *)(obj + 0xaf) & ~8);
                    fn_801723DC(obj);
                    if (*(s8 *)(st + 0x1d) != 0) {
                        fn_80172144(obj);
                    }
                    if (*(s8 *)(st + 0x3e) == 0) {
                        fn_80172824(obj, st);
                    } else {
                        *(s8 *)(st + 0x3e) = *(s8 *)(st + 0x3e) - 1;
                        if (*(s8 *)(st + 0x3e) == 0) {
                            *(u16 *)(st + 0x48) = 0xffff;
                            ObjMsg_SendToObject(Obj_GetPlayerObject(), 0x7000a, obj, st + 0x48);
                        }
                    }
                } else {
                    o = *(int *)(obj + 0x54);
                    if (o != 0) {
                        *(u16 *)(o + 0x60) = (u16)(*(u16 *)(o + 0x60) | 0x100);
                    }
                    ObjHits_DisableObject(obj);
                    if (*(s16 *)(st + 0x10) != -1 && GameBit_Get(*(s16 *)(st + 0x10)) == 0) {
                        *(int *)(obj + 0xf4) = 0;
                    }
                }
            } else {
                if ((*(s16 *)(obj + 6) & 0x2000U) != 0) {
                    *(f32 *)(st + 8) = lbl_803E3450;
                    if (*(int *)(obj + 0x64) != 0) {
                        *(int *)(*(int *)(obj + 0x64) + 0x30) = 0x1000;
                    }
                    itemPickupDoParticleFx(obj, 0xff, 0x28, lbl_803E3454);
                }
                *(f32 *)(st + 0x44) = lbl_803E345C;
            }
        }
    }
}

/* EN v1.0 0x801723DC  size: 676b  fn_801723DC: per-type idle motion. */
void fn_801723DC(int obj)
{
    u8 *st = *(u8 **)(obj + 0xb8);
    s16 v;

    switch (*(s16 *)(obj + 0x46)) {
    case 0xb:
        v = *(s16 *)(st + 0x34) - framesThisStep;
        *(u16 *)(st + 0x34) = v;
        if (v < 1) {
            *(f32 *)(st + 0x30) = (f32)(int)randomGetRange(600, 800);
            *(u16 *)(st + 0x34) = (u16)randomGetRange(0xb4, 0xf0);
            Sfx_PlayFromObject(obj, 0x169);
        }
        *(s16 *)(obj + 2) = (int)*(f32 *)(st + 0x30);
        *(f32 *)(st + 0x30) = *(f32 *)(st + 0x30) * lbl_803E3478;
        if (*(s16 *)(obj + 2) > 9) {
            break;
        }
        if (*(s16 *)(obj + 2) < -9) {
            break;
        }
        *(s16 *)(obj + 2) = 0;
        break;
    case 0x22:
        *(s16 *)obj = lbl_803E347C * timeDelta + (f32)*(s16 *)obj;
        itemPickupDoParticleFx(obj, 10, 1, lbl_803E3454);
        break;
    case 0x27f:
        if (*(f32 *)st < lbl_803E347C) {
            if (randomGetRange(0, 10) == 0) {
                (*(void (**)(int, int, int, int, int, int))((char *)(*gPartfxInterface) + 8))(obj, 0x423, 0, 2, -1, 0);
            }
            *(s16 *)obj = *(s16 *)obj + (s16)(int)(lbl_803E3480 * timeDelta);
        }
        break;
    case 0x5e8:
        *(s16 *)obj = lbl_803E347C * timeDelta + (f32)*(s16 *)obj;
        itemPickupDoParticleFx(obj, 9, 1, lbl_803E3454);
        break;
    case 0x137:
    case 0x12d:
    case 0x135:
    case 0x156:
    case 0x246:
        *(s16 *)obj = lbl_803E347C * timeDelta + (f32)*(s16 *)obj;
        break;
    }
}

/* EN v1.0 0x80172824  size: 672b  fn_80172824: pickup-range test and
 * per-type collect handling. */
void fn_80172824(int obj, u8 *st)
{
    int setup = *(int *)(obj + 0x4c);
    int player;
    int tgt;
    f32 dist, dy;

    player = (int)Obj_GetPlayerObject();
    if (player == 0 || (st[0x37] & 1) != 0) {
        return;
    }
    tgt = fn_802972A8();
    if (tgt == 0) {
        tgt = player;
    }
    dist = Vec_xzDistance((void *)(obj + 0x18), (void *)(tgt + 0x18));
    dy = *(f32 *)(tgt + 0x1c) - *(f32 *)(obj + 0x1c);
    if (dy < lbl_803E345C) {
        dy = -dy;
    }
    if (dy < lbl_803E3490 && dist < *(f32 *)(st + 4) && fn_8029622C(player) != 0) {
        *(u16 *)(st + 0x48) = 0xffff;
        switch (*(s16 *)(obj + 0x46)) {
        case 0x319:
            fn_80171E5C(obj);
            st[0x37] = (u8)(st[0x37] | 1);
            break;
        case 0x49:
        case 0x2da:
        case 0x3cd:
            if (GameBit_Get(0x90f) == 0) {
                ObjMsg_SendToObject(player, 0x7000a, obj, st + 0x48);
                GameBit_Set(0x90f, 1);
            } else {
                fn_80171E5C(obj);
            }
            st[0x37] = (u8)(st[0x37] | 1);
            break;
        case 0xb:
            if (GameBit_Get(0x90e) == 0) {
                ObjMsg_SendToObject(player, 0x7000a, obj, st + 0x48);
                GameBit_Set(0x90e, 1);
            } else {
                fn_80171E5C(obj);
            }
            st[0x37] = (u8)(st[0x37] | 1);
            break;
        case 0x6a6:
            if (GameBit_Get(0x9a8) == 0) {
                ObjMsg_SendToObject(player, 0x7000a, obj, st + 0x48);
                GameBit_Set(0x9a8, 1);
            } else {
                fn_80171E5C(obj);
            }
            st[0x37] = (u8)(st[0x37] | 1);
            break;
        default:
            if (ObjTrigger_IsSet(obj) != 0) {
                GameBit_Set(0xa7b, 1);
                *(u16 *)(st + 0x48) = *(u16 *)(setup + 0x1e);
                ObjMsg_SendToObject(player, 0x7000a, obj, st + 0x48);
                st[0x37] = (u8)(st[0x37] | 1);
                if (*(int *)(obj + 0x64) != 0) {
                    *(int *)(*(int *)(obj + 0x64) + 0x30) = 0x1000;
                }
            }
            break;
        }
    }
    *(f32 *)st = dist;
}

/* EN v1.0 0x80172B1C  size: 260b  collectible_render. */
void collectible_render(int obj, int p2, int p3, int p4, int p5, s8 visible)
{
    u8 *st = *(u8 **)(obj + 0xb8);

    if (visible != 0 && *(f32 *)(st + 8) == lbl_803E345C && *(int *)(obj + 0xf4) == 0 &&
        (*(s16 *)(obj + 0x46) == 0x156 || *(s8 *)(st + 0x1e) == 0)) {
        if ((*(u32 *)(*(int *)(obj + 0x50) + 0x44) & 0x10000) != 0 && *(s8 *)(st + 0x36) != 0) {
            fn_8003B608(st[0x38], st[0x39], st[0x3a]);
        }
        objRenderFn_8003b8f4(lbl_803E3454, obj, p2, p3, p4, p5);
        if (*(s16 *)(obj + 0x46) == 0xa8) {
            objfx_spawnDirectionalBurst(obj, 7, lbl_803E3454, 5, 1, 10, lbl_803E348C, 0, 0x20000000);
        }
    }
}
#pragma peephole reset
#pragma scheduling reset
