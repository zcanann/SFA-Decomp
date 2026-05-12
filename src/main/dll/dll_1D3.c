#include "ghidra_import.h"
#include "main/dll/dll_1D3.h"

extern bool FUN_800067f0();
extern undefined4 FUN_8000680c();
extern undefined4 FUN_80006824();
extern undefined4 FUN_800068cc();
extern undefined4 FUN_800068d0();
extern uint GameBit_Get(int eventId);
extern undefined4 GameBit_Set(int eventId, int value);
extern double FUN_80017708();
extern double FUN_80017714();
extern uint FUN_80017760();
extern int FUN_80017a90();
extern undefined4 FUN_80017ac8();
extern int FUN_80017af8();
extern undefined4 ObjHits_DisableObject();
extern undefined4 ObjHits_EnableObject();
extern undefined4 ObjGroup_FindNearestObject();
extern int ObjTrigger_IsSet();
extern int FUN_80039520();
extern undefined4 FUN_8003a1c4();
extern undefined4 fn_8003A328();
extern undefined4 FUN_8003b1a4();
extern undefined4 FUN_8003b280();
extern undefined4 FUN_8006ef38();
extern undefined4 FUN_8014ccac();
extern int FUN_80163ac8();
extern undefined4 FUN_80163b8c();
extern undefined4 FUN_801cdd1c();
extern undefined8 FUN_80286834();
extern undefined4 FUN_80286880();
extern int FUN_80294c54();
extern uint countLeadingZeros();

extern undefined4 DAT_803274f4;
extern int DAT_8032750c;
extern uint DAT_8032751c;
extern undefined4 DAT_803dcc10;
extern undefined4 DAT_803dcc14;
extern undefined4 DAT_803dcc18;
extern undefined4* DAT_803dd6cc;
extern undefined4* DAT_803dd6d4;
extern undefined4* DAT_803dd6d8;
extern undefined4* DAT_803dd6e8;
extern undefined4* DAT_803dd708;
extern undefined4* DAT_803dd72c;
extern f64 DOUBLE_803e5eb8;
extern f32 lbl_803DC074;
extern f32 lbl_803E5E98;
extern f32 lbl_803E5EA4;
extern f32 lbl_803E5EA8;
extern f32 lbl_803E5EAC;
extern f32 lbl_803E5EB0;
extern f32 lbl_803E5EC0;
extern f32 lbl_803E5EC4;
extern f32 lbl_803E5EC8;
extern f32 lbl_803E5ECC;
extern f32 lbl_803E5ED0;

/*
 * --INFO--
 *
 * Function: FUN_801ce078
 * EN v1.0 Address: 0x801CE078
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x801CE1A0
 * EN v1.1 Size: 140b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801ce078(undefined2 *param_1,int param_2)
{
}

/*
 * --INFO--
 *
 * Function: FUN_801ce07c
 * EN v1.0 Address: 0x801CE07C
 * EN v1.0 Size: 200b
 * EN v1.1 Address: 0x801CE22C
 * EN v1.1 Size: 216b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_801ce07c(int param_1,undefined4 param_2,int param_3)
{
  uint uVar1;
  int iVar2;
  
  uVar1 = GameBit_Get(10);
  if (uVar1 != 0) {
    *(byte *)(param_3 + 0x90) = *(byte *)(param_3 + 0x90) | 4;
  }
  iVar2 = FUN_80039520(param_1,0);
  FUN_80039520(param_1,1);
  *(short *)(iVar2 + 10) = *(short *)(iVar2 + 10) + (short)(int)(lbl_803E5E98 * lbl_803DC074);
  if (0x4e80 < *(short *)(iVar2 + 10)) {
    *(short *)(iVar2 + 10) = *(short *)(iVar2 + 10) + -0x4e80;
  }
  *(ushort *)(param_3 + 0x6e) = *(ushort *)(param_3 + 0x70) & 0xffbf;
  *(undefined *)(param_3 + 0x56) = 0;
  return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_801ce144
 * EN v1.0 Address: 0x801CE144
 * EN v1.0 Size: 68b
 * EN v1.1 Address: 0x801CE304
 * EN v1.1 Size: 64b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801ce144(int param_1)
{
  (**(code **)(*DAT_803dd72c + 0x50))((int)*(char *)(param_1 + 0xac),0x1f,0);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801ce188
 * EN v1.0 Address: 0x801CE188
 * EN v1.0 Size: 176b
 * EN v1.1 Address: 0x801CE344
 * EN v1.1 Size: 224b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801ce188(uint param_1)
{
  uint uVar1;
  
  uVar1 = GameBit_Get(10);
  if (uVar1 == 0) {
    FUN_800068d0(param_1,0x372);
    FUN_800068d0(param_1,0x373);
    (**(code **)(*DAT_803dd6d4 + 0x48))(0,param_1,0xffffffff);
    ObjHits_EnableObject(param_1);
  }
  else {
    *(undefined2 *)(param_1 + 6) = 0x4000;
    *(ushort *)(param_1 + 0xb0) = *(ushort *)(param_1 + 0xb0) | 0x8000;
    FUN_800068cc();
    FUN_800068cc();
    ObjHits_DisableObject(param_1);
    GameBit_Set(0x398,1);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801ce238
 * EN v1.0 Address: 0x801CE238
 * EN v1.0 Size: 12b
 * EN v1.1 Address: 0x801CE424
 * EN v1.1 Size: 12b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int FUN_801ce238(int param_1)
{
  return *(int *)(param_1 + 0xb8) + 0xc;
}

/*
 * --INFO--
 *
 * Function: FUN_801ce244
 * EN v1.0 Address: 0x801CE244
 * EN v1.0 Size: 252b
 * EN v1.1 Address: 0x801CE430
 * EN v1.1 Size: 280b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_801ce244(short *param_1,undefined4 param_2,int param_3)
{
  int iVar1;
  
  iVar1 = *(int *)(param_1 + 0x5c);
  if ((*(byte *)(iVar1 + 0x43c) & 0x20) == 0) {
    FUN_8000680c((int)param_1,0x7f);
    *(float *)(iVar1 + 0x54) = lbl_803E5EA4;
    *(byte *)(iVar1 + 0x43c) = *(byte *)(iVar1 + 0x43c) & 0xef;
    *(byte *)(iVar1 + 0x43c) = *(byte *)(iVar1 + 0x43c) | 0x20;
  }
  if ((*(byte *)(iVar1 + 0x43c) & 4) != 0) {
    *(float *)(iVar1 + 0x18) = lbl_803E5EA4;
    *(ushort *)(param_3 + 0x6e) = *(ushort *)(param_3 + 0x6e) & 0xfff7;
    *(ushort *)(param_3 + 0x6e) = *(ushort *)(param_3 + 0x6e) & 0xffbf;
    FUN_801ce340(param_1,iVar1,1);
  }
  FUN_8006ef38((double)lbl_803E5EA8,(double)lbl_803E5EA8,param_1,iVar1 + 0x440,8,iVar1 + 0x45c,
               iVar1 + 0x16c);
  if (*(char *)(param_3 + 0x8b) != '\0') {
    param_1[0x58] = param_1[0x58] & 0xfbff;
    *(uint *)(*(int *)(param_1 + 0x32) + 0x30) = *(uint *)(*(int *)(param_1 + 0x32) + 0x30) | 4;
  }
  return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_801ce340
 * EN v1.0 Address: 0x801CE340
 * EN v1.0 Size: 228b
 * EN v1.1 Address: 0x801CE548
 * EN v1.1 Size: 228b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801ce340(short *param_1,int param_2,int param_3)
{
  if (((param_3 == 0) || (*(int *)(param_2 + 0x28) == 0)) ||
     (lbl_803E5EAC <= *(float *)(param_2 + 0x18))) {
    *(undefined *)(param_2 + 0x40c) = 0;
  }
  else {
    *(undefined *)(param_2 + 0x40c) = 1;
    *(undefined4 *)(param_2 + 0x410) = *(undefined4 *)(*(int *)(param_2 + 0x28) + 0xc);
    *(undefined4 *)(param_2 + 0x414) = *(undefined4 *)(*(int *)(param_2 + 0x28) + 0x10);
    *(undefined4 *)(param_2 + 0x418) = *(undefined4 *)(*(int *)(param_2 + 0x28) + 0x14);
  }
  if (((&DAT_803274f4)[*(byte *)(param_2 + 0x408)] & 2) == 0) {
    fn_8003A328((double)lbl_803E5EA4,param_1,(char *)(param_2 + 0x40c));
    FUN_8003b280((int)param_1,param_2 + 0x40c);
  }
  else {
    FUN_8003a1c4((int)param_1,param_2 + 0x40c);
    FUN_8003b1a4((int)param_1,param_2 + 0x40c);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801ce424
 * EN v1.0 Address: 0x801CE424
 * EN v1.0 Size: 532b
 * EN v1.1 Address: 0x801CE62C
 * EN v1.1 Size: 580b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_801ce424(uint param_1,int param_2)
{
  byte bVar1;
  float fVar2;
  uint uVar3;
  char cVar4;
  undefined auStack_38 [4];
  undefined auStack_34 [12];
  undefined4 local_28;
  undefined4 local_24;
  undefined4 local_20;
  
  cVar4 = (**(code **)(*DAT_803dd6d8 + 0x24))(auStack_38);
  if (*(char *)(param_2 + 0x45b) == '\0') {
    uVar3 = 0;
  }
  else {
    uVar3 = countLeadingZeros((int)*(char *)(param_2 + 0x453));
    uVar3 = uVar3 >> 5;
  }
  if (*(byte *)(param_2 + 0x408) < 0x14) {
    if (cVar4 == '\0') {
      return 0;
    }
    if (lbl_803E5EA4 < *(float *)(param_2 + 0x54)) {
      return 0xffffffff;
    }
    *(byte *)(param_2 + 0x409) = *(byte *)(param_2 + 0x408);
    *(undefined *)(param_2 + 0x408) = 0x14;
  }
  bVar1 = *(byte *)(param_2 + 0x408);
  if (bVar1 == 0x15) {
    if (uVar3 != 0) {
      FUN_80006824(param_1,0x14c);
    }
    *(float *)(param_2 + 4) = *(float *)(param_2 + 4) - lbl_803DC074;
    if ((cVar4 == '\0') && (*(float *)(param_2 + 4) <= lbl_803E5EA4)) {
      *(undefined *)(param_2 + 0x408) = 0x16;
    }
    fVar2 = *(float *)(param_2 + 0x1c) - lbl_803DC074;
    *(float *)(param_2 + 0x1c) = fVar2;
    if (fVar2 <= lbl_803E5EA4) {
      if ((*(ushort *)(param_1 + 0xb0) & 0x800) != 0) {
        local_28 = *(undefined4 *)(param_2 + 0xc);
        local_24 = *(undefined4 *)(param_2 + 0x10);
        local_20 = *(undefined4 *)(param_2 + 0x14);
        (**(code **)(*DAT_803dd708 + 8))(param_1,0x7f0,auStack_34,0x200001,0xffffffff,0);
      }
      *(float *)(param_2 + 0x1c) = lbl_803E5EB0;
    }
  }
  else if (bVar1 < 0x15) {
    if (0x13 < bVar1) {
      if (uVar3 != 0) {
        FUN_80006824(param_1,0x14b);
      }
      if ((*(byte *)(param_2 + 0x43c) & 2) != 0) {
        *(undefined *)(param_2 + 0x408) = 0x15;
        uVar3 = FUN_80017760(0,300);
        *(float *)(param_2 + 4) =
             (float)((double)CONCAT44(0x43300000,uVar3 ^ 0x80000000) - DOUBLE_803e5eb8);
      }
    }
  }
  else if (bVar1 < 0x17) {
    if (uVar3 != 0) {
      FUN_80006824(param_1,0x14d);
    }
    if ((*(byte *)(param_2 + 0x43c) & 2) != 0) {
      *(undefined *)(param_2 + 0x408) = *(undefined *)(param_2 + 0x409);
    }
  }
  return 1;
}

/*
 * --INFO--
 *
 * Function: FUN_801ce638
 * EN v1.0 Address: 0x801CE638
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x801CE870
 * EN v1.1 Size: 1880b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801ce638(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined4 param_9,undefined4 param_10,int param_11)
{
}

/*
 * --INFO--
 *
 * Function: nw_mammoth_getExtraSize
 * EN v1.0 Address: 0x801CEFB4
 * EN v1.0 Size: 8b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int nw_mammoth_getExtraSize(void)
{
  return 0x48c;
}
