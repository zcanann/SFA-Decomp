#include "ghidra_import.h"
#include "main/dll/IM/IMsnowbike.h"

extern undefined8 FUN_80008b74();
extern undefined8 FUN_80008cbc();
extern undefined4 FUN_8000a538();
extern undefined4 FUN_8000bb38();
extern undefined8 FUN_80014b68();
extern undefined4 FUN_80014b84();
extern undefined4 FUN_80014b94();
extern undefined4 FUN_800168a8();
extern uint FUN_80020078();
extern undefined8 FUN_800201ac();
extern undefined4 FUN_8002b7b0();
extern int FUN_8002bac4();
extern int FUN_8003809c();
extern int FUN_8003811c();
extern undefined4 FUN_8003b9ec();
extern undefined4 FUN_8005517c();
extern undefined8 FUN_80088a84();
extern undefined8 FUN_80088afc();
extern undefined8 FUN_800890e0();
extern int FUN_800e8a48();
extern undefined4 FUN_8011f68c();
extern int FUN_8012f000();
extern undefined4 FUN_801d8204();
extern undefined4 FUN_801d8284();
extern undefined4 FUN_801d86e4();
extern undefined8 FUN_801d88f8();
extern undefined8 FUN_801d8de8();
extern uint FUN_80296c50();

extern short DAT_80328258;
extern undefined4 DAT_8032827c;
extern undefined4 DAT_803282b4;
extern undefined4 DAT_803282ec;
extern undefined4 DAT_80328324;
extern undefined4* DAT_803dd6d4;
extern undefined4* DAT_803dd72c;
extern f32 FLOAT_803dc074;
extern f32 FLOAT_803e614c;
extern f32 FLOAT_803e6158;

/*
 * --INFO--
 *
 * Function: FUN_801d90f0
 * EN v1.0 Address: TODO
 * EN v1.0 Size: TODO
 * EN v1.1 Address: 0x801D90F0
 * EN v1.1 Size: 544b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801d90f0(int param_1,uint *param_2)
{
  uint uVar1;
  int iVar2;
  char cVar3;
  
  uVar1 = FUN_80020078(0x1ab);
  if (uVar1 == 0) {
    if (*(short *)((int)param_2 + 0x12) == 0xcc) {
      *(undefined2 *)((int)param_2 + 0x12) = 0xffff;
    }
  }
  else if (*(short *)((int)param_2 + 0x12) != 0xcc) {
    *(undefined2 *)((int)param_2 + 0x12) = 0xcc;
    FUN_800201ac(0xc0,1);
    *param_2 = *param_2 & 0xfffffffd;
  }
  if (*(byte *)(param_2 + 1) < 2) {
    *(byte *)(param_2 + 1) = *(byte *)(param_2 + 1) + 1;
  }
  else {
    uVar1 = FUN_80020078(0xb);
    if (uVar1 == 0) {
      FUN_80014b94(0);
      FUN_80014b84(0);
      FUN_80014b68(0,0x100);
      FUN_80014b68(0,0x200);
      FUN_80014b68(0,0x1000);
      iVar2 = FUN_8002bac4();
      if ((*(ushort *)(iVar2 + 0xb0) & 0x1000) == 0) {
        (**(code **)(*DAT_803dd6d4 + 0x48))(0,param_1,0xffffffff);
        FUN_800201ac(0xb,1);
      }
    }
    if ((*param_2 & 0x80) == 0) {
      FUN_800201ac(0x2ba,0);
      *param_2 = *param_2 | 0x80;
    }
  }
  uVar1 = FUN_80020078(0x2da);
  if ((((uVar1 == 0) && (uVar1 = FUN_80020078(0x34a), uVar1 != 0)) &&
      (uVar1 = FUN_80020078(0x36f), uVar1 != 0)) &&
     (((uVar1 = FUN_80020078(0x166), uVar1 != 0 && (uVar1 = FUN_80020078(0x167), uVar1 != 0)) &&
      (iVar2 = FUN_8002bac4(), (*(ushort *)(iVar2 + 0xb0) & 0x1000) == 0)))) {
    FUN_800201ac(0x2da,1);
  }
  cVar3 = (**(code **)(*DAT_803dd72c + 0x4c))((int)*(char *)(param_1 + 0xac),6);
  if (cVar3 == '\0') {
    iVar2 = FUN_8002bac4();
    uVar1 = FUN_80296c50(iVar2,0);
    if (uVar1 != 0) {
      (**(code **)(*DAT_803dd72c + 0x50))((int)*(char *)(param_1 + 0xac),6,1);
    }
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801d9310
 * EN v1.0 Address: TODO
 * EN v1.0 Size: TODO
 * EN v1.1 Address: 0x801D9310
 * EN v1.1 Size: 2452b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801d9310(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 uint param_9)
{
}

/*
 * --INFO--
 *
 * Function: FUN_801d9ca4
 * EN v1.0 Address: TODO
 * EN v1.0 Size: TODO
 * EN v1.1 Address: 0x801D9CA4
 * EN v1.1 Size: 380b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801d9ca4(int param_1)
{
}

/*
 * --INFO--
 *
 * Function: FUN_801d9e20
 * EN v1.0 Address: TODO
 * EN v1.0 Size: TODO
 * EN v1.1 Address: 0x801D9E20
 * EN v1.1 Size: 52b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801d9e20(int param_1)
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
 * Function: FUN_801d9e54
 * EN v1.0 Address: TODO
 * EN v1.0 Size: TODO
 * EN v1.1 Address: 0x801D9E54
 * EN v1.1 Size: 444b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801d9e54(int param_1)
{
  byte bVar1;
  bool bVar2;
  int iVar3;
  uint uVar4;
  int iVar5;
  byte *pbVar6;
  short local_18 [8];
  
  pbVar6 = *(byte **)(param_1 + 0xb8);
  bVar2 = false;
  iVar3 = (int)*(char *)(*(int *)(param_1 + 0x58) + 0x10f);
  if ((0 < iVar3) && (iVar5 = 0, 0 < iVar3)) {
    do {
      if (*(short *)(*(int *)(*(int *)(param_1 + 0x58) + iVar5 + 0x100) + 0x44) == 1) {
        bVar2 = true;
      }
      iVar5 = iVar5 + 4;
      iVar3 = iVar3 + -1;
    } while (iVar3 != 0);
  }
  if (bVar2) {
    *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) & 0xf7;
    bVar1 = *pbVar6;
    if (bVar1 == 2) {
      iVar3 = FUN_8003811c(param_1);
      if (iVar3 != 0) {
        FUN_800201ac(0x886,1);
      }
    }
    else if (bVar1 < 2) {
      FUN_8011f68c(local_18);
      uVar4 = FUN_80020078(0xc7c);
      if (((uVar4 == 0) || (iVar3 = FUN_8012f000(), iVar3 == -1)) && (local_18[0] != 0xc7c)) {
        FUN_8002b7b0(param_1,0,0,0,'\0','\x02');
      }
      else {
        FUN_8002b7b0(param_1,0,0,0,'\0','\x04');
      }
      iVar3 = FUN_8003809c(param_1,0xc7c);
      if (iVar3 == 0) {
        iVar3 = FUN_8003811c(param_1);
        if (iVar3 != 0) {
          FUN_800201ac(0xc7e,1);
        }
      }
      else {
        FUN_800201ac(0x886,1);
        FUN_800201ac(0xc7d,1);
        *pbVar6 = 2;
        FUN_8002b7b0(param_1,0,0,0,'\0','\x03');
      }
    }
  }
  else {
    *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) | 8;
  }
  return;
}
