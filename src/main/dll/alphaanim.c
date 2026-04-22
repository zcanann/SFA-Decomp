#include "ghidra_import.h"
#include "main/dll/alphaanim.h"

extern undefined4 FUN_80014b68();
extern uint FUN_80020078();
extern undefined4 FUN_800201ac();
extern undefined4 FUN_8003709c();
extern undefined4 FUN_800372f8();
extern int FUN_8003809c();
extern int FUN_8003811c();
extern undefined4 FUN_8003b9ec();
extern undefined4 FUN_80041110();
extern undefined4 FUN_80055464();
extern undefined4 FUN_8007d858();

extern undefined4* DAT_803dd6d4;

/*
 * --INFO--
 *
 * Function: FUN_8017c250
 * EN v1.0 Address: 0x8017C250
 * EN v1.0 Size: 188b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_8017c250(int param_1,undefined4 param_2,int param_3)
{
  int iVar1;
  
  iVar1 = *(int *)(param_1 + 0x4c);
  if (*(char *)(param_3 + 0x80) != '\0') {
    if (((*(byte *)(iVar1 + 0x1b) & 4) != 0) && (*(char *)(param_3 + 0x80) == '\x01')) {
      FUN_800201ac((int)*(short *)(iVar1 + 0x1c),1);
    }
    if ((*(char *)(param_3 + 0x80) == '\x02') && (*(short *)(iVar1 + 0x24) != 0)) {
      (**(code **)(*DAT_803dd6d4 + 0x58))(param_3);
    }
    *(undefined *)(param_3 + 0x80) = 0;
  }
  *(undefined4 *)(param_1 + 0xf8) = 0;
  return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_8017c30c
 * EN v1.0 Address: 0x8017C30C
 * EN v1.0 Size: 36b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8017c30c(int param_1)
{
  FUN_8003709c(param_1,0xf);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8017c330
 * EN v1.0 Address: 0x8017C330
 * EN v1.0 Size: 80b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8017c330(int param_1)
{
  char in_r8;
  
  if ((in_r8 == '\0') || (*(int *)(param_1 + 0xf8) != 0)) {
    if (*(int *)(param_1 + 0xf8) != 0) {
      FUN_80041110();
    }
  }
  else {
    FUN_8003b9ec(param_1);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8017c380
 * EN v1.0 Address: 0x8017C380
 * EN v1.0 Size: 848b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8017c380(int param_1)
{
  byte bVar1;
  uint uVar2;
  int iVar3;
  int iVar4;
  char *pcVar5;
  
  pcVar5 = *(char **)(param_1 + 0xb8);
  iVar4 = *(int *)(param_1 + 0x4c);
  if (((*(byte *)(param_1 + 0xaf) & 4) == 0) || (uVar2 = FUN_80020078(0x930), uVar2 != 0)) {
    uVar2 = FUN_80020078((int)*(short *)(iVar4 + 0x1c));
    *pcVar5 = (char)uVar2;
    if ((*(byte *)(iVar4 + 0x1b) & 1) == 0) {
      if ((*(ushort *)(iVar4 + 0x26) & 1) != 0) {
        if (*pcVar5 == '\0') {
          *(undefined4 *)(param_1 + 0xf8) = 1;
        }
        else {
          *(undefined4 *)(param_1 + 0xf8) = 0;
        }
      }
    }
    else if (*pcVar5 != '\0') {
      *(undefined *)(param_1 + 0x36) = 0;
    }
    if (*pcVar5 == '\0') {
      *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) & 0xf7;
      *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) & 0xef;
      if ((((int)*(short *)(iVar4 + 0x22) != 0xffffffff) &&
          (uVar2 = FUN_80020078((int)*(short *)(iVar4 + 0x22)), uVar2 == 0)) &&
         (*(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) | 0x10,
         (*(byte *)(iVar4 + 0x1b) & 0x10) != 0)) {
        *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) | 8;
      }
      if (((int)*(short *)(iVar4 + 0x1e) != 0xffffffff) &&
         (uVar2 = FUN_80020078((int)*(short *)(iVar4 + 0x1e)), uVar2 == 0)) {
        *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) | 0x10;
      }
      if (((*(short *)(iVar4 + 0x1e) != -1) &&
          (iVar3 = FUN_8003809c(param_1,*(short *)(iVar4 + 0x1e)), iVar3 != 0)) ||
         ((*(short *)(iVar4 + 0x1e) == -1 && (iVar3 = FUN_8003811c(param_1), iVar3 != 0)))) {
        if (*(char *)(iVar4 + 0x20) != -1) {
          (**(code **)(*DAT_803dd6d4 + 0x48))((int)*(char *)(iVar4 + 0x20),param_1,0xffffffff);
        }
        if ((*(byte *)(iVar4 + 0x1b) & 4) == 0) {
          FUN_800201ac((int)*(short *)(iVar4 + 0x1c),1);
        }
        if ((*(byte *)(iVar4 + 0x1b) & 8) == 0) {
          *pcVar5 = '\x01';
          *(undefined4 *)(param_1 + 0xf4) = 1;
        }
        else {
          FUN_800201ac((int)*(short *)(iVar4 + 0x22),0);
        }
        FUN_80014b68(0,0x100);
      }
    }
    else {
      if (*(int *)(param_1 + 0xf4) == 0) {
        if ((*(char *)(iVar4 + 0x20) != -1) && (*(short *)(iVar4 + 0x24) != 0)) {
          (**(code **)(*DAT_803dd6d4 + 0x54))(param_1);
          uVar2 = 1;
          bVar1 = *(byte *)(iVar4 + 0x1b);
          if ((bVar1 & 0x20) != 0) {
            uVar2 = 3;
          }
          if ((bVar1 & 0x40) != 0) {
            uVar2 = uVar2 | 4;
          }
          if ((bVar1 & 0x80) != 0) {
            uVar2 = uVar2 | 8;
          }
          (**(code **)(*DAT_803dd6d4 + 0x48))((int)*(char *)(iVar4 + 0x20),param_1,uVar2);
        }
        *(undefined4 *)(param_1 + 0xf4) = 1;
      }
      *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) | 8;
    }
    if (((*(uint *)(*(int *)(param_1 + 0x50) + 0x44) & 1) != 0) && (*(int *)(param_1 + 0x74) != 0))
    {
      FUN_80041110();
    }
  }
  else {
    FUN_80014b68(0,0x100);
    (**(code **)(*DAT_803dd6d4 + 0x84))(param_1,0);
    (**(code **)(*DAT_803dd6d4 + 0x48))(1,param_1,0xffffffff);
    FUN_800201ac(0x930,1);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8017c6d0
 * EN v1.0 Address: 0x8017C6D0
 * EN v1.0 Size: 284b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8017c6d0(short *param_1,int param_2)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8017c7ec
 * EN v1.0 Address: 0x8017C7EC
 * EN v1.0 Size: 64b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8017c7ec(int param_1)
{
  if (param_1 != 0) {
    (**(code **)(**(int **)(param_1 + 0x68) + 4))(param_1,*(undefined4 *)(param_1 + 0x4c),0);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8017c82c
 * EN v1.0 Address: 0x8017C82C
 * EN v1.0 Size: 308b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4
FUN_8017c82c(undefined8 param_1,double param_2,double param_3,undefined8 param_4,undefined8 param_5,
            undefined8 param_6,undefined8 param_7,undefined8 param_8,int param_9,undefined4 param_10
            ,int param_11,undefined4 param_12,int param_13,undefined4 param_14,undefined4 param_15,
            undefined4 param_16)
{
  byte bVar1;
  int iVar2;
  int iVar3;
  byte *pbVar4;
  int iVar5;
  
  if (*(short *)(param_9 + 0xb4) != -1) {
    iVar5 = *(int *)(param_9 + 0x4c);
    pbVar4 = *(byte **)(param_9 + 0xb8);
    *(undefined *)(param_11 + 0x56) = 0;
    iVar2 = param_11;
    for (iVar3 = 0; iVar3 < (int)(uint)*(byte *)(param_11 + 0x8b); iVar3 = iVar3 + 1) {
      bVar1 = *(byte *)(param_11 + iVar3 + 0x81);
      if (bVar1 == 2) {
        if (*(byte *)(iVar5 + 0x24) != 0) {
          param_1 = FUN_80055464(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                                 (uint)*(byte *)(iVar5 + 0x24),'\0',iVar2,param_12,param_13,param_14
                                 ,param_15,param_16);
        }
      }
      else if (bVar1 < 2) {
        if (((bVar1 != 0) && ((*(byte *)(iVar5 + 0x1d) & 1) == 0)) &&
           ((*(byte *)(iVar5 + 0x1d) & 2) != 0)) {
          param_1 = FUN_800201ac((int)*(short *)(iVar5 + 0x18),1);
        }
      }
      else if (bVar1 < 4) {
        iVar2 = 0;
        param_12 = 0;
        param_13 = *DAT_803dd6d4;
        param_1 = (**(code **)(param_13 + 0x50))(0x56,1);
      }
    }
    *pbVar4 = *pbVar4 | 4;
  }
  return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_8017c960
 * EN v1.0 Address: 0x8017C960
 * EN v1.0 Size: 36b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8017c960(int param_1)
{
  FUN_8003709c(param_1,0xf);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8017c984
 * EN v1.0 Address: 0x8017C984
 * EN v1.0 Size: 48b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8017c984(int param_1)
{
  char in_r8;
  
  if (in_r8 != '\0') {
    FUN_8003b9ec(param_1);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8017c9b4
 * EN v1.0 Address: 0x8017C9B4
 * EN v1.0 Size: 592b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8017c9b4(int param_1)
{
  uint uVar1;
  byte bVar2;
  int iVar3;
  byte *pbVar4;
  
  pbVar4 = *(byte **)(param_1 + 0xb8);
  iVar3 = *(int *)(param_1 + 0x4c);
  if ((*pbVar4 & 4) != 0) {
    bVar2 = *(byte *)(iVar3 + 0x1d);
    if ((bVar2 & 1) == 0) {
      if ((bVar2 & 8) != 0) {
        FUN_800201ac((int)*(short *)(iVar3 + 0x18),1);
      }
      *pbVar4 = *pbVar4 | 1;
    }
    else if ((bVar2 & 4) == 0) {
      FUN_800201ac((int)*(short *)(iVar3 + 0x1a),0);
    }
    *pbVar4 = *pbVar4 & 0xfb;
  }
  if ((*pbVar4 & 1) == 0) {
    uVar1 = FUN_80020078((int)*(short *)(iVar3 + 0x18));
    if (uVar1 != 0) {
      *pbVar4 = *pbVar4 | 1;
    }
    uVar1 = FUN_80020078((int)*(short *)(iVar3 + 0x1a));
    bVar2 = (byte)uVar1;
    if ((bVar2 != pbVar4[1]) && (pbVar4[1] = bVar2, bVar2 != 0)) {
      if (*(char *)(iVar3 + 0x1e) != -1) {
        (**(code **)(*DAT_803dd6d4 + 0x84))(param_1,0);
        (**(code **)(*DAT_803dd6d4 + 0x48))((int)*(char *)(iVar3 + 0x1e),param_1,0xffffffff);
      }
      if (((*(byte *)(iVar3 + 0x1d) & 1) == 0) && ((*(byte *)(iVar3 + 0x1d) & 10) == 0)) {
        FUN_800201ac((int)*(short *)(iVar3 + 0x18),1);
      }
    }
  }
  else if ((*pbVar4 & 2) == 0) {
    if (((*(byte *)(iVar3 + 0x1d) & 1) != 0) &&
       (uVar1 = FUN_80020078((int)*(short *)(iVar3 + 0x18)), uVar1 == 0)) {
      *pbVar4 = *pbVar4 & 0xfe;
    }
  }
  else {
    (**(code **)(*DAT_803dd6d4 + 0x54))(param_1,(int)*(short *)(iVar3 + 0x20));
    if ((*(byte *)(iVar3 + 0x1d) & 0x10) == 0) {
      (**(code **)(*DAT_803dd6d4 + 0x48))((int)*(char *)(iVar3 + 0x1e),param_1,1);
    }
    else {
      (**(code **)(*DAT_803dd6d4 + 0x48))
                ((int)*(char *)(iVar3 + 0x1e),param_1,*(undefined2 *)(iVar3 + 0x22));
    }
    *pbVar4 = *pbVar4 & 0xfd;
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8017cc04
 * EN v1.0 Address: 0x8017CC04
 * EN v1.0 Size: 248b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8017cc04(short *param_1,int param_2)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8017ccfc
 * EN v1.0 Address: 0x8017CCFC
 * EN v1.0 Size: 232b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_8017ccfc(int param_1,undefined4 param_2,int param_3)
{
  char cVar1;
  int iVar2;
  byte *pbVar3;
  int iVar4;
  
  iVar4 = *(int *)(param_1 + 0x4c);
  pbVar3 = *(byte **)(param_1 + 0xb8);
  for (iVar2 = 0; iVar2 < (int)(uint)*(byte *)(param_3 + 0x8b); iVar2 = iVar2 + 1) {
    cVar1 = *(char *)(param_3 + iVar2 + 0x81);
    if (cVar1 == '\x01') {
      FUN_800201ac((int)*(short *)(iVar4 + 0x18),1);
      FUN_8007d858();
    }
    else if (cVar1 == '\0') {
      FUN_800201ac((int)*(short *)(iVar4 + 0x1a),0);
      FUN_8007d858();
    }
  }
  *pbVar3 = *pbVar3 | 2;
  return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_8017cde4
 * EN v1.0 Address: 0x8017CDE4
 * EN v1.0 Size: 44b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8017cde4(int param_1)
{
  FUN_8003709c(param_1,0xf);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8017ce10
 * EN v1.0 Address: 0x8017CE10
 * EN v1.0 Size: 596b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8017ce10(int param_1)
{
  uint uVar1;
  int iVar2;
  byte *pbVar3;
  
  pbVar3 = *(byte **)(param_1 + 0xb8);
  iVar2 = *(int *)(param_1 + 0x4c);
  if ((*pbVar3 & 1) == 0) {
    if ((*pbVar3 & 2) == 0) {
      if ((((int)*(short *)(iVar2 + 0x1a) == 0xffffffff) ||
          (uVar1 = FUN_80020078((int)*(short *)(iVar2 + 0x1a)), uVar1 != 0)) &&
         (((int)*(short *)(iVar2 + 0x18) == 0xffffffff ||
          (uVar1 = FUN_80020078((int)*(short *)(iVar2 + 0x18)), uVar1 == 0)))) {
        if ((*(byte *)(iVar2 + 0x1d) & 4) != 0) {
          FUN_800201ac((int)*(short *)(iVar2 + 0x1a),0);
          FUN_8007d858();
        }
        if ((*(byte *)(iVar2 + 0x1d) & 0x20) != 0) {
          FUN_800201ac((int)*(short *)(iVar2 + 0x18),1);
          FUN_8007d858();
        }
        FUN_8007d858();
        (**(code **)(*DAT_803dd6d4 + 0x48))((int)*(char *)(iVar2 + 0x1e),param_1,0xffffffff);
      }
    }
    else {
      if ((*(byte *)(iVar2 + 0x1d) & 2) != 0) {
        FUN_800201ac((int)*(short *)(iVar2 + 0x1a),0);
        FUN_8007d858();
      }
      if ((*(byte *)(iVar2 + 0x1d) & 0x10) != 0) {
        FUN_800201ac((int)*(short *)(iVar2 + 0x18),1);
        FUN_8007d858();
      }
      *pbVar3 = *pbVar3 & 0xfd;
    }
  }
  else {
    if ((*(byte *)(iVar2 + 0x1d) & 1) != 0) {
      FUN_800201ac((int)*(short *)(iVar2 + 0x1a),0);
      FUN_8007d858();
    }
    if ((*(byte *)(iVar2 + 0x1d) & 8) != 0) {
      FUN_800201ac((int)*(short *)(iVar2 + 0x18),1);
      FUN_8007d858();
    }
    FUN_8007d858();
    (**(code **)(*DAT_803dd6d4 + 0x54))(param_1,(int)*(short *)(iVar2 + 0x20));
    (**(code **)(*DAT_803dd6d4 + 0x48))
              ((int)*(char *)(iVar2 + 0x1e),param_1,*(undefined2 *)(iVar2 + 0x22));
    *pbVar3 = *pbVar3 & 0xfe;
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8017d064
 * EN v1.0 Address: 0x8017D064
 * EN v1.0 Size: 200b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8017d064(short *param_1,int param_2)
{
}
