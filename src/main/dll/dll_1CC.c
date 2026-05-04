#include "ghidra_import.h"
#include "main/dll/dll_1CC.h"

extern undefined4 FUN_80006b0c();
extern undefined4 FUN_80006b14();
extern uint FUN_80017690();
extern undefined4 FUN_80017698();
extern undefined4 FUN_8001771c();
extern int FUN_80017a98();
extern undefined4 FUN_80017ac8();
extern int ObjGroup_FindNearestObject();
extern int ObjMsg_Pop();
extern int FUN_80286834();
extern undefined4 FUN_80286880();

extern undefined4 DAT_803dc070;
extern undefined4* DAT_803dd6d4;
extern undefined4* DAT_803dd6f0;
extern undefined4* DAT_803dd6fc;
extern undefined4* DAT_803dd72c;
extern f64 DOUBLE_803e5e10;
extern f32 lbl_803E5DF4;
extern f32 lbl_803E5DF8;
extern f32 lbl_803E5DFC;
extern f32 lbl_803E5E00;
extern f32 lbl_803E5E04;
extern f32 lbl_803E5E08;
extern f32 lbl_803E5E0C;

/*
 * --INFO--
 *
 * Function: FUN_801cad80
 * EN v1.0 Address: 0x801CAD80
 * EN v1.0 Size: 2556b
 * EN v1.1 Address: 0x801CB334
 * EN v1.1 Size: 2228b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801cad80(undefined8 param_1,double param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)
{
  int iVar1;
  int iVar2;
  int iVar3;
  int *piVar4;
  short sVar5;
  uint uVar6;
  int iVar7;
  short *psVar8;
  undefined8 extraout_f1;
  undefined8 extraout_f1_00;
  double in_f31;
  double dVar9;
  double in_ps31_1;
  uint uStack_68;
  uint local_64 [2];
  float local_5c [2];
  uint uStack_54;
  longlong local_50;
  undefined4 local_48;
  uint uStack_44;
  undefined8 local_40;
  float local_8;
  float fStack_4;
  
  local_8 = (float)in_f31;
  fStack_4 = (float)in_ps31_1;
  iVar1 = FUN_80286834();
  psVar8 = *(short **)(iVar1 + 0xb8);
  iVar2 = FUN_80017a98();
  local_5c[0] = lbl_803E5DF4;
  *(undefined4 *)(iVar1 + 0x18) = *(undefined4 *)(iVar1 + 0xc);
  *(undefined4 *)(iVar1 + 0x1c) = *(undefined4 *)(iVar1 + 0x10);
  *(undefined4 *)(iVar1 + 0x20) = *(undefined4 *)(iVar1 + 0x14);
  iVar7 = *(int *)(iVar1 + 0xb8);
  local_64[1] = 0;
  while (iVar3 = ObjMsg_Pop(iVar1,local_64,&uStack_68,local_64 + 1), iVar3 != 0) {
    if (local_64[0] == 0x30006) {
      *(undefined2 *)(iVar7 + 6) = 0x10;
    }
    else if (((int)local_64[0] < 0x30006) && (0x30004 < (int)local_64[0])) {
      *(undefined2 *)(iVar7 + 6) = 0xfffd;
    }
  }
  FUN_80017698(0x127,1);
  if (psVar8[3] != 0) {
    psVar8[2] = psVar8[2] + psVar8[3];
    if (psVar8[2] < 0xd) {
      psVar8[2] = 0xc;
      psVar8[3] = 0;
    }
    else if (0x45 < psVar8[2]) {
      psVar8[2] = 0x46;
      psVar8[3] = 0;
    }
    (**(code **)(*DAT_803dd6f0 + 0x38))(2,psVar8[2] & 0xff);
  }
  if (psVar8[5] != 0) {
    psVar8[4] = psVar8[4] + psVar8[5];
    if ((psVar8[4] < 2) && (psVar8[5] < 1)) {
      psVar8[4] = 1;
      psVar8[5] = 0;
    }
    else if ((0x45 < psVar8[4]) && (-1 < psVar8[5])) {
      psVar8[4] = 0x46;
      psVar8[5] = 0;
    }
    (**(code **)(*DAT_803dd6f0 + 0x38))(3,psVar8[4] & 0xff);
  }
  if (psVar8[1] < 1) {
    iVar7 = ObjGroup_FindNearestObject(0xe,iVar2,local_5c);
    if (((iVar7 != 0) && (local_5c[0] < lbl_803E5DF8)) && (lbl_803E5DFC < local_5c[0])) {
      dVar9 = (double)(*(float *)(iVar7 + 0x14) - *(float *)(iVar2 + 0x14));
      if (dVar9 <= (double)lbl_803E5E00) {
        if (dVar9 < (double)lbl_803E5E00) {
          dVar9 = (double)(float)(dVar9 * (double)lbl_803E5E04);
        }
        if (psVar8[4] != 0x1e) {
          psVar8[4] = 0x1e;
        }
        uStack_54 = (int)psVar8[4] ^ 0x80000000;
        local_5c[1] = 176.0;
        uVar6 = (uint)((float)((double)CONCAT44(0x43300000,uStack_54) - DOUBLE_803e5e10) *
                      ((float)(dVar9 - (double)lbl_803E5DFC) / lbl_803E5E08));
        local_50 = (longlong)(int)uVar6;
        if ((short)uVar6 < 1) {
          uVar6 = 1;
        }
        (**(code **)(*DAT_803dd6f0 + 0x38))(3,uVar6 & 0xff);
        uStack_44 = (int)psVar8[2] ^ 0x80000000;
        local_48 = 0x43300000;
        param_2 = (double)(float)((double)CONCAT44(0x43300000,uStack_44) - DOUBLE_803e5e10);
        uVar6 = (uint)(param_2 *
                      (double)((lbl_803E5E08 - (float)(dVar9 - (double)lbl_803E5DFC)) /
                              lbl_803E5E08));
        local_40 = (double)(longlong)(int)uVar6;
        if ((short)uVar6 < 1) {
          uVar6 = 1;
        }
        (**(code **)(*DAT_803dd6f0 + 0x38))(2,uVar6 & 0xff);
      }
    }
    switch(*(undefined *)((int)psVar8 + 0xf)) {
    case 0:
      uVar6 = FUN_80017690(0x5b5);
      if ((uVar6 == 0) && (uVar6 = FUN_80017690(0x594), uVar6 != 0)) {
        FUN_80017698(0x5b5,1);
      }
      FUN_80017698(0x5b9,0);
      dVar9 = (double)FUN_8001771c((float *)(iVar1 + 0x18),(float *)(iVar2 + 0x18));
      local_40 = (double)CONCAT44(0x43300000,(int)*psVar8 ^ 0x80000000);
      if (dVar9 < (double)(float)(local_40 - DOUBLE_803e5e10)) {
        *(undefined *)((int)psVar8 + 0xf) = 1;
        FUN_80017698(0x129,0);
        (**(code **)(*DAT_803dd6d4 + 0x48))(0,iVar1,0xffffffff);
        piVar4 = (int *)FUN_80006b14(0x83);
        (**(code **)(*piVar4 + 4))(iVar1,0,0,1,0xffffffff,0);
        FUN_80006b0c((undefined *)piVar4);
        piVar4 = (int *)FUN_80006b14(0x84);
        (**(code **)(*piVar4 + 4))(iVar1,0,0,1,0xffffffff,0);
        FUN_80006b0c((undefined *)piVar4);
        FUN_80017698(0x126,0);
        (**(code **)(*DAT_803dd6fc + 0x20))(psVar8 + 6);
      }
      break;
    case 1:
      if (*(char *)(psVar8 + 8) == '\x01') {
        *(undefined *)((int)psVar8 + 0xf) = 2;
        psVar8[1] = 0xa0;
      }
      break;
    case 2:
      if ((*(char *)(psVar8 + 7) == '\0') && (uVar6 = FUN_80017690(0x1cd), uVar6 == 0)) {
        FUN_80017698(0x1cd,1);
      }
      uVar6 = FUN_80017690(0x5b2);
      if (uVar6 != 0) {
        *(char *)(psVar8 + 7) = *(char *)(psVar8 + 7) + '\x01';
        psVar8[1] = 100;
        if (*(char *)(psVar8 + 7) == '\x01') {
          (**(code **)(*DAT_803dd6d4 + 0x48))(3,iVar1,0xffffffff);
        }
      }
      break;
    case 3:
      local_5c[0] = lbl_803E5E0C;
      iVar2 = ObjGroup_FindNearestObject(3,iVar1,local_5c);
      if (iVar2 != 0) {
        FUN_80017ac8(extraout_f1_00,param_2,param_3,param_4,param_5,param_6,param_7,param_8,iVar2);
      }
      uVar6 = FUN_80017690(0x1ce);
      if (uVar6 == 0) {
        FUN_80017698(0x126,0);
        (**(code **)(*DAT_803dd6f0 + 0x18))(3,0x2a,0x50,psVar8[4] & 0xff,0);
        psVar8[5] = 1;
        (**(code **)(*DAT_803dd6d4 + 0x48))(1,iVar1,0xffffffff);
      }
      else {
        psVar8[4] = 1;
        (**(code **)(*DAT_803dd6f0 + 0x18))(3,0x2c,0x50,psVar8[4] & 0xff,0);
        psVar8[5] = 1;
        FUN_80017698(0x129,1);
        *(undefined *)((int)psVar8 + 0xf) = 5;
      }
      break;
    case 4:
      uVar6 = FUN_80017690(0xfd);
      if (uVar6 == 0) {
        FUN_80017698(0xfd,1);
      }
      FUN_80017698(0x1cf,0);
      FUN_80017698(0x127,0);
      *(undefined *)((int)psVar8 + 0xf) = 5;
      (**(code **)(*DAT_803dd6f0 + 0x18))(3,0x2c,0x50,psVar8[4] & 0xff,0);
      FUN_80017698(0x1ce,1);
      (**(code **)(*DAT_803dd72c + 0x44))(0xb,6);
      break;
    case 6:
      (**(code **)(*DAT_803dd6f0 + 0x18))(3,0x35,0x50,psVar8[4] & 0xff,0);
      psVar8[5] = 1;
      (**(code **)(*DAT_803dd6d4 + 0x48))(2,iVar1,0xffffffff);
      local_5c[0] = lbl_803E5E0C;
      iVar2 = ObjGroup_FindNearestObject(3,iVar1,local_5c);
      if (iVar2 != 0) {
        FUN_80017ac8(extraout_f1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,iVar2);
      }
      *(undefined *)((int)psVar8 + 0xf) = 0;
      psVar8[1] = 400;
      FUN_80017698(0x129,1);
      FUN_80017698(0x126,1);
      FUN_80017698(0x127,1);
      FUN_80017698(0x5b2,0);
      FUN_80017698(0x5b9,1);
      piVar4 = (int *)FUN_80006b14(0x6a);
      sVar5 = (**(code **)(*piVar4 + 4))(iVar1,0,0,0x402,0xffffffff,0);
      psVar8[6] = sVar5;
      FUN_80006b0c((undefined *)piVar4);
      FUN_80017698(0x1cd,0);
      *(undefined *)(psVar8 + 7) = 0;
      *(undefined *)(psVar8 + 8) = 0;
      break;
    case 7:
      (**(code **)(*DAT_803dd6d4 + 0x48))(5,iVar1,0xffffffff);
      *(undefined *)((int)psVar8 + 0xf) = 3;
      psVar8[1] = 0;
      psVar8[5] = -3;
      break;
    case 8:
      (**(code **)(*DAT_803dd6d4 + 0x48))(4,iVar1,0xffffffff);
      *(undefined *)((int)psVar8 + 0xf) = 6;
      psVar8[1] = 0;
      psVar8[5] = -3;
    }
  }
  else {
    psVar8[1] = psVar8[1] - (ushort)DAT_803dc070;
    if ((psVar8[1] < 1) && (psVar8[1] = 0, *(char *)(psVar8 + 9) == '\0')) {
      (**(code **)(*DAT_803dd6f0 + 0x18))(3,0x2c,0x50,(int)psVar8[4],0);
      *(undefined *)(psVar8 + 9) = 1;
    }
  }
  FUN_80286880();
  return;
}


/* Trivial 4b 0-arg blr leaves. */
void fn_801CB7A0(void) {}
void fn_801CB7A4(void) {}
void fn_801CB7B8(void) {}
void fn_801CB7EC(void) {}
void fn_801CBA90(void) {}
void fn_801CBA94(void) {}

/* 8b "li r3, N; blr" returners. */
int fn_801CB7A8(void) { return 0x4; }
int fn_801CB7B0(void) { return 0x0; }

/* render-with-fn_8003B8F4 pattern. */
extern f32 lbl_803E5180;
extern void fn_8003B8F4(f32);
#pragma peephole off
void fn_801CB7BC(int p1, int p2, int p3, int p4, int p5, s8 visible) { s32 v = visible; if (v != 0) fn_8003B8F4(lbl_803E5180); }
#pragma peephole reset
