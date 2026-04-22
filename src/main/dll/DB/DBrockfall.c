#include "ghidra_import.h"
#include "main/dll/DB/DBrockfall.h"

extern uint FUN_80014e9c();
extern undefined4 FUN_800168a8();
extern undefined8 FUN_80019940();
extern uint FUN_80020078();
extern undefined4 FUN_800201ac();
extern int FUN_8002bac4();
extern undefined4 FUN_8003b9ec();
extern undefined4 FUN_80041110();
extern undefined4 FUN_80088554();
extern undefined4 FUN_8011f670();
extern int FUN_80286838();
extern undefined4 FUN_80286884();
extern int FUN_80296ffc();
extern undefined4 FUN_8029700c();
extern uint countLeadingZeros();

extern undefined4 DAT_80328730;
extern undefined4 DAT_80328734;
extern undefined4* DAT_803dd6d4;
extern undefined4* DAT_803dd72c;
extern undefined4 DAT_803de890;
extern f32 FLOAT_803e6310;

/*
 * --INFO--
 *
 * Function: FUN_801df458
 * EN v1.0 Address: 0x801DF458
 * EN v1.0 Size: 40b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801df458(int param_1)
{
  FUN_8003b9ec(param_1);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801df480
 * EN v1.0 Address: 0x801DF480
 * EN v1.0 Size: 640b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801df480(undefined2 *param_1)
{
  bool bVar1;
  byte bVar2;
  short sVar3;
  float fVar4;
  int iVar5;
  char cVar7;
  undefined4 uVar6;
  undefined4 *puVar8;
  
  puVar8 = *(undefined4 **)(param_1 + 0x5c);
  FUN_8002bac4();
  FUN_800201ac(0xf1d,0);
  cVar7 = (**(code **)(*DAT_803dd72c + 0x40))(0xe);
  if (cVar7 == '\x06') {
    if ((*(byte *)(puVar8 + 0xc) & 4) == 0) {
      if ((*(byte *)(puVar8 + 0xc) & 2) != 0) {
        sVar3 = *(short *)((int)puVar8 + 0x2e);
        if (sVar3 == 0) {
          *param_1 = 0xd700;
          puVar8[8] = 0xffffd700;
          puVar8[10] = puVar8[8];
          fVar4 = FLOAT_803e6310;
          puVar8[1] = FLOAT_803e6310;
          puVar8[2] = fVar4;
          *(undefined2 *)((int)puVar8 + 0x2e) = 1;
          *(byte *)(puVar8 + 0xc) = *(byte *)(puVar8 + 0xc) & 0xfe;
        }
        else if (sVar3 == 1) {
          FUN_800201ac(0xf1d,1);
          FUN_8011f670(1);
          uVar6 = (**(code **)(*DAT_803dd6d4 + 0x48))(0,param_1,0xffffffff);
          puVar8[9] = uVar6;
        }
        else if (sVar3 == 2) {
          *(undefined2 *)((int)puVar8 + 0x2e) = 0;
        }
        else if (sVar3 == 3) {
          *(undefined2 *)((int)puVar8 + 0x2e) = 0;
        }
      }
    }
    else {
      if (0 < (int)puVar8[9]) {
        (**(code **)(*DAT_803dd6d4 + 0x4c))();
        FUN_80088554(puVar8[9]);
      }
      iVar5 = DAT_803de890 + -1;
      bVar1 = DAT_803de890 == 0;
      DAT_803de890 = iVar5;
      if (bVar1) {
        *(byte *)(puVar8 + 0xc) = *(byte *)(puVar8 + 0xc) & 0xfb;
        *(undefined4 *)(param_1 + 6) = puVar8[3];
        *(undefined4 *)(param_1 + 8) = puVar8[4];
        *(undefined4 *)(param_1 + 10) = puVar8[5];
        *puVar8 = 0;
        *param_1 = 0xd700;
        puVar8[8] = 0xffffd700;
        bVar2 = *(byte *)(puVar8 + 0xc);
        if ((bVar2 & 8) == 0) {
          if ((bVar2 & 0x10) != 0) {
            *(byte *)(puVar8 + 0xc) = bVar2 & 0xef;
            puVar8[9] = 0xffffffff;
            FUN_800201ac(0x786,1);
          }
        }
        else {
          FUN_800201ac(0x784,1);
          puVar8[9] = 0xffffffff;
          *(byte *)(puVar8 + 0xc) = *(byte *)(puVar8 + 0xc) & 0xfc;
          *(byte *)(puVar8 + 0xc) = *(byte *)(puVar8 + 0xc) & 0xf7;
        }
      }
    }
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801df700
 * EN v1.0 Address: 0x801DF700
 * EN v1.0 Size: 220b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
uint FUN_801df700(int param_1,undefined4 param_2,int param_3)
{
  bool bVar1;
  int iVar2;
  uint uVar3;
  int iVar4;
  int iVar5;
  
  iVar5 = *(int *)(param_1 + 0x4c);
  iVar4 = *(int *)(param_1 + 0xb8);
  iVar2 = FUN_8002bac4();
  uVar3 = FUN_80014e9c(0);
  if ((uVar3 & 0x100) == 0) {
    uVar3 = 0;
  }
  else {
    *(undefined *)(iVar4 + 2) = 0;
    iVar2 = FUN_80296ffc(iVar2);
    bVar1 = iVar2 < *(short *)(iVar5 + 0x1a);
    if (bVar1) {
      *(undefined *)(iVar4 + 2) = 2;
    }
    else {
      *(undefined *)(iVar4 + 2) = 0;
    }
    uVar3 = (uint)!bVar1;
    if (param_3 == 0x15) {
      uVar3 = countLeadingZeros(uVar3);
      uVar3 = uVar3 >> 5;
    }
    else if ((param_3 < 0x15) && (0x13 < param_3)) {
      uVar3 = countLeadingZeros(1 - uVar3);
      uVar3 = uVar3 >> 5;
    }
    else {
      uVar3 = 0;
    }
  }
  return uVar3;
}

/*
 * --INFO--
 *
 * Function: FUN_801df7dc
 * EN v1.0 Address: 0x801DF7DC
 * EN v1.0 Size: 316b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801df7dc(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined4 param_9,undefined4 param_10,int param_11)
{
}

/*
 * --INFO--
 *
 * Function: FUN_801df918
 * EN v1.0 Address: 0x801DF918
 * EN v1.0 Size: 276b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801df918(int param_1)
{
  byte bVar1;
  uint uVar2;
  byte *pbVar3;
  
  pbVar3 = *(byte **)(param_1 + 0xb8);
  bVar1 = *pbVar3;
  if (bVar1 == 1) {
    if ((*(byte *)(param_1 + 0xaf) & 1) != 0) {
      (**(code **)(*DAT_803dd6d4 + 0x48))(0,param_1,0xffffffff);
    }
    *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) & 0xf7;
  }
  else if (bVar1 == 0) {
    uVar2 = (uint)*(short *)(*(int *)(param_1 + 0x4c) + 0x1e);
    if ((uVar2 == 0xffffffff) || (uVar2 = FUN_80020078(uVar2), uVar2 == 0)) {
      *pbVar3 = 1;
    }
    else {
      *pbVar3 = 2;
    }
  }
  else if (bVar1 < 3) {
    *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) | 8;
  }
  pbVar3[2] = 0;
  if (((*(uint *)(*(int *)(param_1 + 0x50) + 0x44) & 1) != 0) && (*(int *)(param_1 + 0x74) != 0)) {
    FUN_80041110();
  }
  return;
}
