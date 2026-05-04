#include "ghidra_import.h"
#include "main/dll/projball1D8.h"

extern undefined4 FUN_800067c0();
extern undefined4 FUN_80006824();
extern byte FUN_80006b20();
extern double FUN_80006b3c();
extern byte FUN_80006b44();
extern undefined4 FUN_80006b4c();
extern undefined4 FUN_80006b50();
extern undefined4 FUN_80006b54();
extern undefined4 FUN_80006c88();
extern uint FUN_80017690();
extern undefined4 FUN_80017698();
extern undefined4 FUN_80017a98();
extern undefined4 FUN_80080f14();
extern int FUN_801d025c();
extern undefined4 FUN_801d8308();
extern int FUN_80286840();
extern undefined4 FUN_8028688c();

extern undefined4* DAT_803dd6d4;
extern undefined4* DAT_803dd6d8;
extern undefined4* DAT_803dd72c;
extern f32 lbl_803DC074;
extern f32 lbl_803E5F10;
extern f32 lbl_803E5F14;

/*
 * --INFO--
 *
 * Function: nw_levcontrol_update
 * EN v1.0 Address: 0x801CFF20
 * EN v1.0 Size: 228b
 * EN v1.1 Address: 0x801D049C
 * EN v1.1 Size: 84b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void nw_levcontrol_update(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                          undefined8 param_5,undefined8 param_6,undefined8 param_7,
                          undefined8 param_8,int param_9)
{
  char cVar1;
  undefined8 extraout_f1;
  
  cVar1 = (**(code **)(*DAT_803dd72c + 0x4c))((int)*(char *)(param_9 + 0xac),0);
  if (cVar1 == '\0') {
    FUN_80080f14(extraout_f1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0);
  }
  FUN_80006b4c();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801d0004
 * EN v1.0 Address: 0x801D0004
 * EN v1.0 Size: 1832b
 * EN v1.1 Address: 0x801D04F0
 * EN v1.1 Size: 1472b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801d0004(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)
{
  int iVar1;
  short *psVar2;
  char cVar7;
  int iVar3;
  uint uVar4;
  uint uVar5;
  byte bVar8;
  float fVar6;
  uint uVar9;
  float *pfVar10;
  double dVar11;
  double dVar12;
  
  iVar1 = FUN_80286840();
  pfVar10 = *(float **)(iVar1 + 0xb8);
  psVar2 = (short *)FUN_80017a98();
  if ((double)lbl_803E5F10 < (double)*pfVar10) {
    FUN_80006c88((double)*pfVar10,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0x435);
    *pfVar10 = *pfVar10 - lbl_803DC074;
    if (*pfVar10 < lbl_803E5F10) {
      *pfVar10 = lbl_803E5F10;
    }
  }
  cVar7 = (**(code **)(*DAT_803dd72c + 0x40))((int)*(char *)(iVar1 + 0xac));
  if (cVar7 != '\x01') {
    (**(code **)(*DAT_803dd72c + 0x44))((int)*(char *)(iVar1 + 0xac),1);
  }
  cVar7 = (**(code **)(*DAT_803dd72c + 0x40))(7);
  if (cVar7 == '\x01') {
    (**(code **)(*DAT_803dd72c + 0x44))(7,2);
    FUN_80017698(0xf22,1);
    FUN_80017698(0xf23,1);
    FUN_80017698(0xf24,1);
    FUN_80017698(0xf25,1);
  }
  iVar3 = (**(code **)(*DAT_803dd6d8 + 0x24))(0);
  if (iVar3 == 0) {
    if ((*(short *)(pfVar10 + 4) != 0x1a) &&
       (*(undefined2 *)(pfVar10 + 4) = 0x1a, ((uint)pfVar10[2] & 0x10) != 0)) {
      FUN_800067c0((int *)0x1a,1);
    }
  }
  else if ((*(short *)(pfVar10 + 4) != -1) &&
          (*(undefined2 *)(pfVar10 + 4) = 0xffff, ((uint)pfVar10[2] & 0x10) != 0)) {
    FUN_800067c0((int *)0x1a,0);
  }
  FUN_801d8308(pfVar10 + 2,8,-1,-1,0x3a0,(int *)0x35);
  FUN_801d8308(pfVar10 + 2,0x10,-1,-1,0x3a1,(int *)(int)*(short *)(pfVar10 + 4));
  FUN_801d8308(pfVar10 + 2,0x20,-1,-1,0x393,(int *)0x36);
  FUN_801d8308(pfVar10 + 2,0x40,-1,-1,0xcbb,(int *)0xc4);
  uVar9 = 0;
  uVar4 = FUN_80017690(0x19f);
  uVar5 = FUN_80017690(0x19d);
  if ((uVar5 != uVar4) && (bVar8 = FUN_80006b20(), bVar8 != 0)) {
    uVar9 = 1;
  }
  FUN_80017698(0xf31,uVar9);
  FUN_801d8308(pfVar10 + 2,0x80,-1,-1,0xf31,(int *)0xaf);
  uVar4 = FUN_80017690(0x398);
  if ((uVar4 != 0) &&
     (cVar7 = (**(code **)(*DAT_803dd72c + 0x4c))((int)*(char *)(iVar1 + 0xac),0x1f), cVar7 == '\0')
     ) {
    (**(code **)(*DAT_803dd72c + 0x50))((int)*(char *)(iVar1 + 0xac),0x1f,1);
  }
  if ((((uint)pfVar10[2] & 2) == 0) || (bVar8 = FUN_80006b44(), bVar8 == 0)) {
    switch(*(undefined *)(pfVar10 + 1)) {
    case 0:
      uVar4 = FUN_80017690(0x19d);
      if (uVar4 != 0) {
        (**(code **)(*DAT_803dd6d4 + 0x48))(0,iVar1,0xffffffff);
        *(undefined *)(pfVar10 + 1) = 2;
        FUN_80017698(0xecd,1);
      }
      break;
    case 1:
      (**(code **)(*DAT_803dd6d4 + 0x54))(iVar1,0x64a);
      (**(code **)(*DAT_803dd6d4 + 0x48))(0,iVar1,0x20);
      *(undefined *)(pfVar10 + 1) = 2;
      FUN_80017698(0xecd,1);
      break;
    case 2:
      iVar1 = FUN_801d025c((int)pfVar10);
      if (iVar1 != 0) {
        *(undefined *)((int)pfVar10 + 5) = 0x32;
        pfVar10[2] = (float)((uint)pfVar10[2] | 1);
      }
      break;
    case 3:
    case 4:
    case 5:
    case 6:
    case 7:
      FUN_801d025c((int)pfVar10);
      break;
    case 8:
      iVar1 = FUN_801d025c((int)pfVar10);
      if (iVar1 == 1) {
        pfVar10[2] = (float)((uint)pfVar10[2] | 4);
      }
      break;
    case 9:
      if ((psVar2[0x58] & 0x1000U) != 0) {
        *(undefined *)(pfVar10 + 1) = 10;
      }
      break;
    case 10:
      if ((psVar2[0x58] & 0x1000U) == 0) {
        fVar6 = pfVar10[2];
        if (((uint)fVar6 & 1) == 0) {
          if (((uint)fVar6 & 4) == 0) {
            dVar12 = FUN_80006b3c();
            dVar11 = (double)lbl_803E5F14;
            FUN_80006b4c();
            FUN_80006b54(0x15,(uint)*(byte *)((int)pfVar10 + 5) + (int)(dVar12 / dVar11));
            FUN_80006b50();
          }
          else {
            pfVar10[2] = (float)((uint)fVar6 & 0xfffffffd);
            pfVar10[2] = (float)((uint)pfVar10[2] & 0xfffffffb);
            FUN_80006b4c();
            FUN_800067c0((int *)0xaf,0);
            FUN_80017698(0x19f,1);
          }
        }
        else {
          pfVar10[2] = (float)((uint)fVar6 & 0xfffffffe);
          pfVar10[2] = (float)((uint)pfVar10[2] | 2);
          FUN_80006b54(0x15,(uint)*(byte *)((int)pfVar10 + 5));
          FUN_80006b50();
          (**(code **)(*DAT_803dd72c + 0x1c))(psVar2 + 6,(int)*psVar2,0,0);
        }
        (**(code **)(*DAT_803dd6d4 + 0x48))(*(undefined *)(pfVar10 + 3),iVar1,0xffffffff);
        *(undefined *)(pfVar10 + 1) = *(undefined *)((int)pfVar10 + 0xd);
      }
      break;
    case 0xb:
      uVar4 = FUN_80017690(0xecd);
      if (uVar4 != 0) {
        FUN_80017698(0xecd,0);
      }
      break;
    case 0xc:
      (**(code **)(*DAT_803dd6d4 + 0x54))(iVar1,0x5a);
      (**(code **)(*DAT_803dd6d4 + 0x48))(1,iVar1,8);
      *(undefined *)(pfVar10 + 1) = 0xb;
    }
  }
  else {
    FUN_80006824(0,0x28d);
    (**(code **)(*DAT_803dd72c + 0x28))();
  }
  FUN_8028688c();
  return;
}

/*
 * --INFO--
 *
 * Function: sh_tricky_getExtraSize
 * EN v1.0 Address: 0x801D069C
 * EN v1.0 Size: 8b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int sh_tricky_getExtraSize(void)
{
  return 1;
}
