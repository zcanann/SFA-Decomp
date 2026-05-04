#include "ghidra_import.h"
#include "main/tex_dolphin.h"

extern undefined4 FUN_80017598();
extern double FUN_800175dc();
extern undefined4 FUN_800175e4();
extern undefined4 FUN_8001760c();
extern char FUN_80048094();
extern int FUN_800480a0();
extern undefined4 FUN_8004812c();
extern undefined4 FUN_800487e0();
extern undefined4 FUN_80048bc4();
extern undefined4 FUN_80049260();
extern undefined4 FUN_8004938c();
extern undefined4 FUN_80049390();
extern undefined4 FUN_80049910();
extern undefined4 FUN_80049ee0();
extern undefined4 FUN_80049fb0();
extern undefined4 FUN_8004a094();
extern undefined4 FUN_8004a2c4();
extern undefined4 FUN_8004a394();
extern undefined4 FUN_8004a670();
extern undefined4 FUN_8004a94c();
extern undefined4 FUN_8004ac40();
extern undefined4 FUN_8004c178();
extern undefined4 FUN_80051868();
extern undefined4 FUN_80051b04();
extern undefined4 FUN_800523e4();
extern undefined4 FUN_80052500();
extern undefined4 FUN_800528d0();
extern undefined4 FUN_80052904();
extern int FUN_8005375c();
extern undefined4 FUN_8005d5f4();
extern void newshadows_getShadowTextureTable16();
extern undefined4 FUN_8006f8a4();
extern undefined4 FUN_8006f8fc();
extern void trackIntersect_drawColorBand(void);
extern void trackIntersect_getColorRgb();
extern undefined4 FUN_80080f00();
extern undefined4 FUN_80080f88();
extern uint FUN_801184b8();
extern undefined4 FUN_80247618();
extern undefined4 FUN_80247a48();
extern undefined4 FUN_80247bf8();
extern undefined4 FUN_80259288();
extern undefined4 FUN_8025a2ec();
extern undefined4 FUN_8025a5bc();
extern undefined4 FUN_8025a608();
extern undefined4 FUN_8025b9e8();
extern undefined4 FUN_8025c224();
extern undefined4 FUN_8025c754();
extern undefined4 FUN_8025ca38();
extern undefined4 FUN_8025cce8();
extern undefined4 FUN_8025d63c();
extern undefined4 FUN_8025d80c();
extern ulonglong FUN_80286820();
extern undefined8 FUN_80286838();
extern undefined8 FUN_8028683c();
extern undefined4 FUN_8028686c();
extern undefined4 FUN_80286884();
extern undefined4 FUN_80286888();

extern undefined4 DAT_802c25c0;
extern undefined4 DAT_802c25c4;
extern undefined4 DAT_802c25c8;
extern undefined4 DAT_802c25cc;
extern undefined4 DAT_802c25d0;
extern undefined4 DAT_802c25d4;
extern undefined4 DAT_8037ed2c;
extern undefined4 DAT_80382c68;
extern undefined4 DAT_80388538;
extern undefined4 DAT_8038859c;
extern undefined4 DAT_803dc29c;
extern undefined4 DAT_803dc2a0;
extern undefined4 DAT_803dc2a4;
extern undefined4 DAT_803ddaa0;
extern int DAT_803ddaa8;
extern undefined4 DAT_803ddab0;
extern undefined4 DAT_803ddab4;
extern undefined4 DAT_803ddae8;
extern int* DAT_803ddaec;
extern undefined4 DAT_803df830;
extern undefined4 DAT_803e90c4;
extern undefined4 DAT_803e90c8;
extern f64 DOUBLE_803df840;
extern f32 lbl_803DDA58;
extern f32 lbl_803DDA5C;
extern f32 lbl_803DF848;
extern f32 lbl_803DF84C;
extern f32 lbl_803DF87C;
extern f32 lbl_803DF8A0;
extern f32 lbl_803DF8A4;
extern f32 lbl_803DF8A8;
extern f32 lbl_803DF8AC;
extern void* PTR_LAB_8030f404;

/*
 * --INFO--
 *
 * Function: FUN_8005df5c
 * EN v1.0 Address: 0x8005DF5C
 * EN v1.0 Size: 232b
 * EN v1.1 Address: 0x8005E0D8
 * EN v1.1 Size: 1004b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_8005df5c(undefined4 param_1,float *param_2)
{
  undefined4 uVar1;
  int iVar2;
  uint uVar3;
  double dVar4;
  double dVar5;
  float local_58;
  float local_54;
  float local_50;
  
  uVar3 = 0;
  iVar2 = 0;
  dVar4 = (double)lbl_803DF8A0;
  dVar5 = (double)lbl_803DF8A8;
  while( true ) {
    if (uVar3 < 8) {
                    /* WARNING: Could not recover jumptable at 0x8005e134. Too many branches */
                    /* WARNING: Treating indirect jump as call */
      uVar1 = (**(code **)((int)&PTR_LAB_8030f404 + iVar2))();
      return uVar1;
    }
    local_58 = (float)((double)local_58 * dVar4);
    local_54 = (float)((double)local_54 * dVar4);
    local_50 = (float)((double)local_50 * dVar4);
    FUN_80247bf8(param_2,&local_58,&local_58);
    if (dVar5 <= (double)local_50) break;
    uVar3 = uVar3 + 1;
    iVar2 = iVar2 + 4;
    if (7 < (int)uVar3) {
      return 0;
    }
  }
  return 1;
}

/*
 * --INFO--
 *
 * Function: FUN_8005e044
 * EN v1.0 Address: 0x8005E044
 * EN v1.0 Size: 536b
 * EN v1.1 Address: 0x8005E4C4
 * EN v1.1 Size: 536b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8005e044(undefined4 param_1,undefined4 param_2,int *param_3,float *param_4)
{
  undefined uVar1;
  undefined uVar2;
  undefined uVar3;
  int iVar4;
  uint uVar5;
  undefined4 *puVar6;
  double in_f28;
  double dVar7;
  double in_f29;
  double dVar8;
  double in_f30;
  double dVar9;
  double in_f31;
  double dVar10;
  double in_ps28_1;
  double in_ps29_1;
  double in_ps30_1;
  double in_ps31_1;
  undefined8 uVar11;
  int local_b8;
  undefined4 uStack_b4;
  float local_b0;
  undefined4 local_ac;
  undefined4 local_a8;
  undefined4 local_a4;
  float local_a0;
  undefined4 local_9c;
  float afStack_98 [12];
  undefined4 local_68;
  uint uStack_64;
  undefined4 local_60;
  uint uStack_5c;
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
  uVar11 = FUN_8028683c();
  uVar5 = param_3[4];
  uVar3 = *(undefined *)(*param_3 + ((int)uVar5 >> 3));
  iVar4 = *param_3 + ((int)uVar5 >> 3);
  uVar1 = *(undefined *)(iVar4 + 1);
  uVar2 = *(undefined *)(iVar4 + 2);
  param_3[4] = uVar5 + 8;
  puVar6 = (undefined4 *)
           (*(int *)((int)((ulonglong)uVar11 >> 0x20) + 0x68) +
           ((uint3)(CONCAT12(uVar2,CONCAT11(uVar1,uVar3)) >> (uVar5 & 7)) & 0xff) * 0x1c);
  uVar5 = *(uint *)((int)uVar11 + 0x3c);
  if ((uVar5 & 0x4000) == 0) {
    if ((uVar5 & 0x8000) == 0) {
      if ((uVar5 & 0x10000) == 0) goto LAB_8005e6a4;
      iVar4 = 0x10;
    }
    else {
      iVar4 = 8;
    }
  }
  else {
    iVar4 = 4;
  }
  dVar7 = (double)lbl_803DF8AC;
  dVar9 = (double)lbl_803DF8A4;
  dVar10 = (double)lbl_803DF87C;
  dVar8 = DOUBLE_803df840;
  for (uVar5 = 0; (int)uVar5 < iVar4; uVar5 = uVar5 + 1) {
    uStack_64 = uVar5 + 1 ^ 0x80000000;
    local_68 = 0x43300000;
    FUN_80247a48((double)lbl_803DF84C,
                 (double)(float)(dVar7 * (double)(float)((double)CONCAT44(0x43300000,uStack_64) -
                                                        dVar8)),(double)lbl_803DF84C,afStack_98);
    FUN_80247618(param_4,afStack_98,afStack_98);
    FUN_8025d80c(afStack_98,0);
    local_b0 = DAT_802c25c0;
    local_ac = DAT_802c25c4;
    local_a8 = DAT_802c25c8;
    local_a4 = DAT_802c25cc;
    local_a0 = (float)DAT_802c25d0;
    local_9c = DAT_802c25d4;
    newshadows_getShadowTextureTable16(&local_b8,&uStack_b4);
    FUN_8004812c(*(int *)(local_b8 + (uVar5 & 0xff) * 4),1);
    uStack_5c = (uVar5 & 0xff) + 1 ^ 0x80000000;
    local_60 = 0x43300000;
    local_b0 = (float)((double)(float)((double)(float)((double)CONCAT44(0x43300000,uStack_5c) -
                                                      dVar8) * dVar9) * dVar10);
    local_a0 = local_b0;
    FUN_8025b9e8(1,&local_b0,DAT_803dc2a4);
    FUN_8025d63c(*puVar6,(uint)*(ushort *)(puVar6 + 1));
  }
LAB_8005e6a4:
  FUN_80286888();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8005e25c
 * EN v1.0 Address: 0x8005E25C
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x8005E6DC
 * EN v1.1 Size: 464b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int FUN_8005e25c(int param_1,int *param_2)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_8005e264
 * EN v1.0 Address: 0x8005E264
 * EN v1.0 Size: 756b
 * EN v1.1 Address: 0x8005E8AC
 * EN v1.1 Size: 588b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8005e264(undefined4 param_1,undefined4 param_2,float *param_3)
{
  int iVar1;
  int iVar2;
  int *piVar3;
  double dVar4;
  undefined8 uVar5;
  byte local_68;
  byte local_67;
  byte local_66;
  undefined uStack_65;
  int local_64;
  float fStack_60;
  undefined4 uStack_5c;
  undefined4 auStack_58 [2];
  undefined4 local_50;
  uint uStack_4c;
  undefined4 local_48;
  uint uStack_44;
  undefined4 local_40;
  uint uStack_3c;
  undefined4 local_38;
  uint uStack_34;
  undefined4 local_30;
  uint uStack_2c;
  undefined4 local_28;
  uint uStack_24;
  
  uVar5 = FUN_80286838();
  iVar2 = (int)((ulonglong)uVar5 >> 0x20);
  iVar1 = (int)uVar5;
  uStack_4c = (int)*(short *)(iVar2 + 6) >> 3 ^ 0x80000000;
  local_50 = 0x43300000;
  uStack_44 = (int)*(short *)(iVar2 + 8) >> 3 ^ 0x80000000;
  local_48 = 0x43300000;
  uStack_3c = (int)*(short *)(iVar2 + 10) >> 3 ^ 0x80000000;
  local_40 = 0x43300000;
  uStack_34 = (int)*(short *)(iVar2 + 0xc) >> 3 ^ 0x80000000;
  local_38 = 0x43300000;
  uStack_2c = (int)*(short *)(iVar2 + 0xe) >> 3 ^ 0x80000000;
  local_30 = 0x43300000;
  uStack_24 = (int)*(short *)(iVar2 + 0x10) >> 3 ^ 0x80000000;
  local_28 = 0x43300000;
  FUN_8001760c((double)((float)((double)CONCAT44(0x43300000,uStack_4c) - DOUBLE_803df840) +
                        *(float *)(iVar1 + 0x18) + lbl_803DDA58),
               (double)((float)((double)CONCAT44(0x43300000,uStack_44) - DOUBLE_803df840) +
                       *(float *)(iVar1 + 0x28)),
               (double)((float)((double)CONCAT44(0x43300000,uStack_3c) - DOUBLE_803df840) +
                        *(float *)(iVar1 + 0x38) + lbl_803DDA5C),
               (double)((float)((double)CONCAT44(0x43300000,uStack_34) - DOUBLE_803df840) +
                        *(float *)(iVar1 + 0x18) + lbl_803DDA58),
               (double)((float)((double)CONCAT44(0x43300000,uStack_2c) - DOUBLE_803df840) +
                       *(float *)(iVar1 + 0x28)),
               (double)((float)((double)CONCAT44(0x43300000,uStack_24) - DOUBLE_803df840) +
                        *(float *)(iVar1 + 0x38) + lbl_803DDA5C),&DAT_803ddaa0,2,&local_64);
  FUN_80052904();
  FUN_800487e0(param_3);
  piVar3 = (int *)&DAT_803ddaa0;
  for (iVar2 = 0; iVar2 < local_64; iVar2 = iVar2 + 1) {
    FUN_80017598(*piVar3,&local_68,&local_67,&local_66,&uStack_65);
    local_68 = (char)((int)(uint)local_68 >> 1) + (char)((int)(uint)local_68 >> 2);
    local_67 = (char)((int)(uint)local_67 >> 1) + (char)((int)(uint)local_67 >> 2);
    local_66 = (char)((int)(uint)local_66 >> 1) + (char)((int)(uint)local_66 >> 2);
    FUN_800175e4(*piVar3,&fStack_60,&uStack_5c,auStack_58);
    dVar4 = FUN_800175dc(*piVar3);
    FUN_8004a94c(dVar4,(undefined4 *)&local_68,&fStack_60);
    piVar3 = piVar3 + 1;
  }
  FUN_800528d0();
  FUN_8025a5bc(1);
  FUN_80259288(2);
  FUN_8006f8fc(1,3,0);
  FUN_8006f8a4(1);
  FUN_8025cce8(1,4,5,5);
  FUN_8025c754(7,0,0,7,0);
  FUN_80286884();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8005e558
 * EN v1.0 Address: 0x8005E558
 * EN v1.0 Size: 288b
 * EN v1.1 Address: 0x8005EAF8
 * EN v1.1 Size: 296b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4
FUN_8005e558(double param_1,double param_2,double param_3,double param_4,double param_5,
            double param_6,float *param_7)
{
  byte bVar1;
  float *pfVar2;
  int iVar3;
  double dVar4;
  double dVar5;
  double dVar6;
  double dVar7;
  double dVar8;
  double dVar9;
  
  pfVar2 = (float *)&DAT_8038859c;
  iVar3 = 5;
  while( true ) {
    bVar1 = *(byte *)(pfVar2 + 4);
    dVar5 = param_1;
    dVar8 = param_2;
    if ((bVar1 & 1) != 0) {
      dVar5 = param_2;
      dVar8 = param_1;
    }
    dVar4 = param_3;
    dVar7 = param_4;
    if ((bVar1 & 2) != 0) {
      dVar4 = param_4;
      dVar7 = param_3;
    }
    dVar6 = param_6;
    dVar9 = param_5;
    if ((bVar1 & 4) != 0) {
      dVar6 = param_5;
      dVar9 = param_6;
    }
    if ((*param_7 +
         pfVar2[3] +
         (float)(dVar9 * (double)pfVar2[2] +
                (double)(float)(dVar5 * (double)*pfVar2 + (double)(float)(dVar4 * (double)pfVar2[1])
                               )) < lbl_803DF84C) &&
       (*param_7 +
        pfVar2[3] +
        (float)(dVar6 * (double)pfVar2[2] +
               (double)(float)(dVar8 * (double)*pfVar2 + (double)(float)(dVar7 * (double)pfVar2[1]))
               ) < lbl_803DF84C)) break;
    pfVar2 = pfVar2 + 5;
    param_7 = param_7 + 1;
    iVar3 = iVar3 + -1;
    if (iVar3 == 0) {
      return 1;
    }
  }
  return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_8005e678
 * EN v1.0 Address: 0x8005E678
 * EN v1.0 Size: 524b
 * EN v1.1 Address: 0x8005EC20
 * EN v1.1 Size: 476b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4
FUN_8005e678(int param_1,int param_2,float *param_3,int param_4,float *param_5,float *param_6,
            float *param_7,float *param_8,float *param_9,float *param_10)
{
  byte bVar1;
  float fVar2;
  float fVar3;
  float fVar4;
  float fVar5;
  float fVar6;
  float fVar7;
  double dVar8;
  
  dVar8 = DOUBLE_803df840;
  *param_8 = (float)((double)CONCAT44(0x43300000,(int)*(short *)(param_1 + 0xc) >> 3 ^ 0x80000000) -
                    DOUBLE_803df840) + *(float *)(param_2 + 0x18);
  *param_5 = (float)((double)CONCAT44(0x43300000,(int)*(short *)(param_1 + 6) >> 3 ^ 0x80000000) -
                    dVar8) + *(float *)(param_2 + 0x18);
  *param_9 = (float)((double)CONCAT44(0x43300000,(int)*(short *)(param_1 + 0xe) >> 3 ^ 0x80000000) -
                    dVar8) + *(float *)(param_2 + 0x28);
  *param_6 = (float)((double)CONCAT44(0x43300000,(int)*(short *)(param_1 + 8) >> 3 ^ 0x80000000) -
                    dVar8) + *(float *)(param_2 + 0x28);
  *param_10 = (float)((double)CONCAT44(0x43300000,(int)*(short *)(param_1 + 0x10) >> 3 ^ 0x80000000)
                     - dVar8) + *(float *)(param_2 + 0x38);
  *param_7 = (float)((double)CONCAT44(0x43300000,(int)*(short *)(param_1 + 10) >> 3 ^ 0x80000000) -
                    dVar8) + *(float *)(param_2 + 0x38);
  if (0 < param_4) {
    do {
      bVar1 = *(byte *)(param_3 + 4);
      if ((bVar1 & 1) == 0) {
        fVar2 = *param_5;
        fVar3 = *param_8;
      }
      else {
        fVar2 = *param_8;
        fVar3 = *param_5;
      }
      if ((bVar1 & 2) == 0) {
        fVar4 = *param_6;
        fVar5 = *param_9;
      }
      else {
        fVar4 = *param_9;
        fVar5 = *param_6;
      }
      if ((bVar1 & 4) == 0) {
        fVar6 = *param_7;
        fVar7 = *param_10;
      }
      else {
        fVar6 = *param_10;
        fVar7 = *param_7;
      }
      if ((param_3[3] + fVar6 * param_3[2] + fVar2 * *param_3 + fVar4 * param_3[1] < lbl_803DF84C)
         && (param_3[3] + fVar7 * param_3[2] + fVar3 * *param_3 + fVar5 * param_3[1] <
             lbl_803DF84C)) {
        return 0;
      }
      param_3 = param_3 + 5;
      param_4 = param_4 + -1;
    } while (param_4 != 0);
  }
  return 1;
}

/*
 * --INFO--
 *
 * Function: FUN_8005e884
 * EN v1.0 Address: 0x8005E884
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8005EDFC
 * EN v1.1 Size: 1376b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8005e884(undefined4 param_1,undefined4 param_2,int param_3,int param_4,int *param_5,
                 float *param_6)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8005e888
 * EN v1.0 Address: 0x8005E888
 * EN v1.0 Size: 900b
 * EN v1.1 Address: 0x8005F35C
 * EN v1.1 Size: 888b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8005e888(int param_1)
{
  int iVar1;
  int *piVar2;
  int iVar3;
  float *pfVar4;
  int *piVar5;
  int iVar6;
  int iVar7;
  undefined4 local_48;
  float afStack_44 [13];
  
  local_48 = DAT_803df830;
  if ((*(char *)(param_1 + 0x41) == '\x02') &&
     (iVar1 = FUN_800480a0(param_1,1), (*(byte *)(iVar1 + 4) & 0x7f) == 9)) {
    piVar2 = (int *)FUN_800480a0(param_1,0);
    if (*(char *)((int)piVar2 + 5) == '\0') {
      iVar1 = *piVar2;
    }
    else {
      iVar1 = *piVar2;
      iVar3 = 0;
      iVar6 = 0x50;
      piVar5 = DAT_803ddaec;
      do {
        if (((0 < *(short *)(piVar5 + 3)) && (*piVar5 == iVar1)) &&
           (*(char *)((int)piVar2 + 5) == *(char *)((int)piVar5 + 0xe))) {
          iVar1 = FUN_8005375c(iVar1,DAT_803ddaec[iVar3 * 4 + 1]);
          break;
        }
        piVar5 = piVar5 + 4;
        iVar3 = iVar3 + 1;
        iVar6 = iVar6 + -1;
      } while (iVar6 != 0);
    }
    if (*(byte *)((int)piVar2 + 6) == 0xff) {
      pfVar4 = (float *)0x0;
    }
    else {
      iVar3 = (uint)*(byte *)((int)piVar2 + 6) * 0x10;
      FUN_80247a48((double)(*(float *)(DAT_803ddae8 + iVar3) / lbl_803DF848),
                   (double)(*(float *)(DAT_803ddae8 + iVar3 + 4) / lbl_803DF848),
                   (double)lbl_803DF84C,afStack_44);
      pfVar4 = afStack_44;
    }
    FUN_80051b04(iVar1,pfVar4,0,(char *)&local_48);
    if ((*(uint *)(param_1 + 0x3c) & 0x100) != 0) {
      FUN_80049260();
    }
    piVar2 = (int *)FUN_800480a0(param_1,1);
    if (*(char *)((int)piVar2 + 5) == '\0') {
      iVar1 = *piVar2;
    }
    else {
      iVar1 = *piVar2;
      iVar3 = 0;
      iVar6 = 0x50;
      piVar5 = DAT_803ddaec;
      do {
        if (((0 < *(short *)(piVar5 + 3)) && (*piVar5 == iVar1)) &&
           (*(char *)((int)piVar2 + 5) == *(char *)((int)piVar5 + 0xe))) {
          iVar1 = FUN_8005375c(iVar1,DAT_803ddaec[iVar3 * 4 + 1]);
          break;
        }
        piVar5 = piVar5 + 4;
        iVar3 = iVar3 + 1;
        iVar6 = iVar6 + -1;
      } while (iVar6 != 0);
    }
    if (*(byte *)((int)piVar2 + 6) == 0xff) {
      pfVar4 = (float *)0x0;
    }
    else {
      iVar3 = (uint)*(byte *)((int)piVar2 + 6) * 0x10;
      FUN_80247a48((double)(*(float *)(DAT_803ddae8 + iVar3) / lbl_803DF848),
                   (double)(*(float *)(DAT_803ddae8 + iVar3 + 4) / lbl_803DF848),
                   (double)lbl_803DF84C,afStack_44);
      pfVar4 = afStack_44;
    }
    FUN_80051868(iVar1,pfVar4,9);
    FUN_80052500((char *)&local_48);
  }
  else {
    for (iVar1 = 0; iVar1 < (int)(uint)*(byte *)(param_1 + 0x41); iVar1 = iVar1 + 1) {
      piVar2 = (int *)FUN_800480a0(param_1,iVar1);
      iVar3 = *piVar2;
      if (iVar3 == 0) {
        FUN_800523e4();
      }
      else {
        if (*(char *)((int)piVar2 + 5) != '\0') {
          iVar6 = 0;
          iVar7 = 0x50;
          piVar5 = DAT_803ddaec;
          do {
            if (((0 < *(short *)(piVar5 + 3)) && (*piVar5 == iVar3)) &&
               (*(char *)((int)piVar2 + 5) == *(char *)((int)piVar5 + 0xe))) {
              iVar3 = FUN_8005375c(iVar3,DAT_803ddaec[iVar6 * 4 + 1]);
              break;
            }
            piVar5 = piVar5 + 4;
            iVar6 = iVar6 + 1;
            iVar7 = iVar7 + -1;
          } while (iVar7 != 0);
        }
        if (*(byte *)((int)piVar2 + 6) == 0xff) {
          pfVar4 = (float *)0x0;
        }
        else {
          pfVar4 = (float *)(DAT_803ddae8 + (uint)*(byte *)((int)piVar2 + 6) * 0x10);
          FUN_80247a48((double)(*pfVar4 / lbl_803DF848),(double)(pfVar4[1] / lbl_803DF848),
                       (double)lbl_803DF84C,afStack_44);
          pfVar4 = afStack_44;
        }
        if ((*(uint *)(param_1 + 0x3c) & 0x40000) == 0) {
          FUN_80051868(iVar3,pfVar4,*(byte *)(piVar2 + 1) & 0x7f);
        }
        else {
          FUN_8004c178(iVar3,pfVar4);
        }
      }
    }
    if ((*(uint *)(param_1 + 0x3c) & 0x100) != 0) {
      FUN_80049260();
    }
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8005ec0c
 * EN v1.0 Address: 0x8005EC0C
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x8005F6D4
 * EN v1.1 Size: 968b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int FUN_8005ec0c(char param_1,int param_2,int *param_3)
{
    return 0;
}
