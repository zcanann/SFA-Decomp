#include "ghidra_import.h"
#include "main/dll/torch1D9.h"

extern undefined4 FUN_80008b74();
extern undefined4 FUN_80008cbc();
extern uint FUN_80020078();
extern undefined4 FUN_800201ac();
extern int FUN_8002ba84();
extern undefined4 FUN_8002bac4();
extern undefined8 FUN_80088a84();
extern undefined4 FUN_80088afc();
extern int FUN_800e8a48();

extern undefined4 DAT_8032768c;
extern undefined4 DAT_803276c4;
extern undefined4 DAT_803276fc;
extern undefined4 DAT_80327734;
extern undefined4* DAT_803dd72c;
extern f32 FLOAT_803e5f18;

/*
 * --INFO--
 *
 * Function: FUN_801d0ab0
 * EN v1.0 Address: TODO
 * EN v1.0 Size: TODO
 * EN v1.1 Address: 0x801D0AB0
 * EN v1.1 Size: 452b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801d0ab0(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9)
{
  uint uVar1;
  int iVar2;
  undefined4 in_r7;
  undefined4 in_r8;
  undefined4 in_r9;
  undefined4 in_r10;
  float *pfVar3;
  undefined8 extraout_f1;
  undefined8 uVar4;
  
  pfVar3 = *(float **)(param_9 + 0xb8);
  FUN_8002bac4();
  *(ushort *)(param_9 + 0xb0) = *(ushort *)(param_9 + 0xb0) | 0x6000;
  uVar1 = FUN_80020078(0x19f);
  if (uVar1 == 0) {
    uVar1 = FUN_80020078(0x19d);
    if (uVar1 == 0) {
      *(undefined *)(pfVar3 + 1) = 0;
    }
    else {
      *(undefined *)(pfVar3 + 1) = 1;
    }
  }
  else {
    *(undefined *)(pfVar3 + 1) = 0xc;
  }
  *pfVar3 = FLOAT_803e5f18;
  FUN_80088afc(&DAT_803276c4,&DAT_8032768c,&DAT_803276fc,&DAT_80327734);
  iVar2 = FUN_800e8a48();
  if (iVar2 == 0) {
    uVar4 = FUN_80088a84(extraout_f1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0x1f);
    FUN_80008cbc(uVar4,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0,0,0x23c,0,in_r7,
                 in_r8,in_r9,in_r10);
  }
  else {
    uVar4 = FUN_80088a84(extraout_f1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0x3f);
    FUN_80008b74(uVar4,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0,0,0x23c,0,in_r7,
                 in_r8,in_r9,in_r10);
  }
  (**(code **)(*DAT_803dd72c + 0x50))(7,0,0);
  (**(code **)(*DAT_803dd72c + 0x50))(7,2,0);
  (**(code **)(*DAT_803dd72c + 0x50))(7,5,0);
  (**(code **)(*DAT_803dd72c + 0x50))(7,10,0);
  (**(code **)(*DAT_803dd72c + 0x50))(7,0x1c,0);
  (**(code **)(*DAT_803dd72c + 0x50))(7,9,1);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801d0c74
 * EN v1.0 Address: TODO
 * EN v1.0 Size: TODO
 * EN v1.1 Address: 0x801D0C74
 * EN v1.1 Size: 284b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801d0c74(int param_1)
{
  byte bVar1;
  int iVar2;
  uint uVar3;
  byte *pbVar4;
  
  pbVar4 = *(byte **)(param_1 + 0xb8);
  iVar2 = FUN_8002ba84();
  if (iVar2 != 0) {
    bVar1 = *pbVar4;
    if (bVar1 == 2) {
      iVar2 = (**(code **)(**(int **)(iVar2 + 0x68) + 0x38))(iVar2,param_1);
      if (iVar2 != 0) {
        *pbVar4 = 3;
      }
    }
    else if (bVar1 < 2) {
      if (bVar1 == 0) {
        uVar3 = FUN_80020078(0x94);
        if (uVar3 != 0) {
          FUN_800201ac(0x4e4,0);
          FUN_800201ac(0x4e5,0);
          FUN_800201ac(0xc11,1);
          *pbVar4 = 1;
        }
      }
      else {
        *pbVar4 = 2;
      }
    }
    else if (((bVar1 != 4) && (bVar1 < 4)) && (uVar3 = FUN_80020078(0xbf), uVar3 != 0)) {
      FUN_800201ac(0x4e4,1);
      FUN_800201ac(0x4e5,1);
      FUN_800201ac(0xc11,0);
    }
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801d0d90
 * EN v1.0 Address: TODO
 * EN v1.0 Size: TODO
 * EN v1.1 Address: 0x801D0D90
 * EN v1.1 Size: 156b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801d0d90(int param_1)
{
  uint uVar1;
  undefined *puVar2;
  
  puVar2 = *(undefined **)(param_1 + 0xb8);
  uVar1 = FUN_80020078(0xbf);
  if (uVar1 == 0) {
    *puVar2 = 0;
  }
  else {
    uVar1 = FUN_80020078(0x4e4);
    if (uVar1 == 0) {
      FUN_800201ac(0xbf,0);
    }
    else {
      *puVar2 = 4;
    }
  }
  *(ushort *)(param_1 + 0xb0) = *(ushort *)(param_1 + 0xb0) | 0x6000;
  return;
}
