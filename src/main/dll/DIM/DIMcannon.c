#include "ghidra_import.h"
#include "main/dll/DIM/DIMcannon.h"

extern undefined4 FUN_80006724();
extern undefined8 FUN_80006728();
extern undefined4 FUN_800067c0();
extern undefined4 FUN_80006824();
extern undefined4 FUN_80017540();
extern undefined4 FUN_80017544();
extern undefined4 FUN_8001754c();
extern undefined4 FUN_8001759c();
extern undefined4 FUN_800175b0();
extern int FUN_800175c4();
extern undefined4 FUN_800175d0();
extern undefined4 FUN_80017620();
extern void* FUN_80017624();
extern undefined8 FUN_80017640();
extern uint GameBit_Get(int eventId);
extern undefined4 GameBit_Set(int eventId, int value);
extern undefined4 FUN_8001771c();
extern undefined4 FUN_80017748();
extern uint FUN_80017760();
extern undefined4 FUN_80017814();
extern int FUN_80017830();
extern undefined8 FUN_800178e4();
extern undefined4 FUN_800178e8();
extern undefined4 FUN_80017a88();
extern int FUN_80017a90();
extern int FUN_80017a98();
extern void* FUN_80017aa4();
extern undefined4 FUN_80017ac8();
extern undefined8 FUN_80017ae4();
extern uint FUN_80017ae8();
extern int FUN_80017af8();
extern int FUN_80017b00();
extern undefined4 FUN_8002fc3c();
extern undefined4 FUN_800305f8();
extern undefined4 ObjHits_DisableObject();
extern undefined4 ObjHits_EnableObject();
extern void* ObjGroup_GetObjects();
extern undefined4 ObjPath_GetPointWorldPosition();
extern int FUN_80039520();
extern undefined4 FUN_8003b818();
extern undefined4 FUN_80057690();
extern int FUN_8005b024();
extern undefined4 FUN_8005fe14();
extern undefined8 FUN_80080f14();
extern undefined8 FUN_80080f18();
extern undefined8 FUN_80080f28();
extern undefined4 FUN_8008112c();
extern int FUN_800e8b98();
extern undefined4 FUN_80135c84();
extern undefined4 FUN_801adca0();
extern undefined4 FUN_801d8308();
extern undefined8 FUN_80286830();
extern int FUN_8028683c();
extern int FUN_80286840();
extern undefined4 FUN_8028687c();
extern undefined4 FUN_80286888();
extern undefined4 FUN_8028688c();
extern undefined4 FUN_80293f90();
extern undefined4 FUN_80294964();

extern undefined4 DAT_802c2a88;
extern undefined4 DAT_802c2a8c;
extern undefined4 DAT_802c2a90;
extern undefined4 DAT_802c2a98;
extern undefined4 DAT_802c2a9c;
extern undefined4 DAT_802c2aa0;
extern undefined4 DAT_80324458;
extern undefined4 DAT_80324464;
extern undefined4 DAT_80324518;
extern undefined4 DAT_80324550;
extern undefined4 DAT_80324588;
extern undefined4 DAT_803245c0;
extern undefined4 DAT_80324630;
extern undefined4 DAT_80324668;
extern undefined4 DAT_803246a0;
extern undefined4 DAT_803246d8;
extern undefined4 DAT_803ad5a8;
extern undefined4 DAT_803ad5b4;
extern undefined4 DAT_803ad5b8;
extern undefined4 DAT_803ad5bc;
extern undefined4 DAT_803dc070;
extern undefined4* DAT_803dd6d4;
extern undefined4* DAT_803dd6d8;
extern undefined4* DAT_803dd6f8;
extern undefined4* DAT_803dd708;
extern undefined4* DAT_803dd72c;
extern undefined4 DAT_803de7c8;
extern f64 DOUBLE_803e53e8;
extern f64 DOUBLE_803e5438;
extern f64 DOUBLE_803e5480;
extern f64 DOUBLE_803e54b0;
extern f32 lbl_803DC074;
extern f32 lbl_803E53E0;
extern f32 lbl_803E53E4;
extern f32 lbl_803E53F0;
extern f32 lbl_803E53F4;
extern f32 lbl_803E53F8;
extern f32 lbl_803E53FC;
extern f32 lbl_803E5408;
extern f32 lbl_803E540C;
extern f32 lbl_803E5410;
extern f32 lbl_803E5414;
extern f32 lbl_803E541C;
extern f32 lbl_803E5420;
extern f32 lbl_803E5424;
extern f32 lbl_803E5428;
extern f32 lbl_803E542C;
extern f32 lbl_803E5430;
extern f32 lbl_803E5440;
extern f32 lbl_803E5444;
extern f32 lbl_803E5448;
extern f32 lbl_803E544C;
extern f32 lbl_803E545C;
extern f32 lbl_803E5460;
extern f32 lbl_803E5468;
extern f32 lbl_803E546C;
extern f32 lbl_803E5470;
extern f32 lbl_803E548C;
extern f32 lbl_803E5490;
extern f32 lbl_803E5494;
extern f32 lbl_803E5498;
extern f32 lbl_803E549C;
extern f32 lbl_803E54A0;
extern f32 lbl_803E54AC;

/*
 * --INFO--
 *
 * Function: imicepillar_render
 * EN v1.0 Address: 0x801AE100
 * EN v1.0 Size: 132b
 * EN v1.1 Address: 0x801AE134
 * EN v1.1 Size: 44b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void imicepillar_render(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9)
{
  if (*(int *)(param_9 + 200) != 0) {
    FUN_80017ac8(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                 *(int *)(param_9 + 200));
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801ae184
 * EN v1.0 Address: 0x801AE184
 * EN v1.0 Size: 360b
 * EN v1.1 Address: 0x801AE160
 * EN v1.1 Size: 380b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801ae184(undefined4 param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4,
                 undefined4 param_5,char param_6)
{
  undefined uVar1;
  bool bVar2;
  undefined2 *puVar3;
  uint uVar4;
  int iVar5;
  undefined4 uVar6;
  undefined2 *puVar7;
  undefined4 *puVar8;
  undefined8 uVar9;
  
  uVar9 = FUN_80286830();
  puVar3 = (undefined2 *)((ulonglong)uVar9 >> 0x20);
  if (puVar3[0x23] == 0x373) {
    FUN_8003b818((int)puVar3);
  }
  else {
    uVar4 = GameBit_Get(0x6e);
    if ((uVar4 == 0) || (uVar4 = GameBit_Get(0x382), uVar4 != 0)) {
      puVar8 = *(undefined4 **)(puVar3 + 0x5c);
      puVar7 = (undefined2 *)*puVar8;
      bVar2 = false;
      if ((puVar7 != (undefined2 *)0x0) &&
         (iVar5 = (**(code **)(**(int **)(puVar7 + 0x34) + 0x38))(puVar7), iVar5 == 2)) {
        bVar2 = true;
      }
      if (bVar2) {
        puVar3[3] = puVar3[3] | 8;
        uVar6 = FUN_80057690((int)puVar7);
        param_6 = (char)uVar6;
        FUN_801adca0(puVar3,puVar7,(int)uVar9,param_3,param_4,param_5,param_6,
                     (uint)*(byte *)(puVar8 + 8),1);
      }
      else {
        puVar3[3] = puVar3[3] & 0xfff7;
      }
      if ((param_6 != '\0') && (*(char *)(puVar8 + 8) != '\0')) {
        uVar1 = *(undefined *)((int)puVar3 + 0x37);
        if (bVar2) {
          *(char *)((int)puVar3 + 0x37) = *(char *)(puVar8 + 8);
        }
        FUN_8003b818((int)puVar3);
        ObjPath_GetPointWorldPosition(puVar3,1,(float *)(puVar8 + 5),puVar8 + 6,(float *)(puVar8 + 7),0);
        *(undefined *)((int)puVar3 + 0x37) = uVar1;
      }
    }
  }
  FUN_8028687c();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801ae2ec
 * EN v1.0 Address: 0x801AE2EC
 * EN v1.0 Size: 140b
 * EN v1.1 Address: 0x801AE2DC
 * EN v1.1 Size: 136b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801ae2ec(undefined2 *param_1)
{
  int iVar1;
  int *piVar2;
  
  piVar2 = *(int **)(param_1 + 0x5c);
  iVar1 = *piVar2;
  if ((iVar1 != 0) && (iVar1 = (**(code **)(**(int **)(iVar1 + 0x68) + 0x38))(), iVar1 == 2)) {
    FUN_801adca0(param_1,(undefined2 *)*piVar2,0,0,0,0,'\0',0,0);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801ae378
 * EN v1.0 Address: 0x801AE378
 * EN v1.0 Size: 1000b
 * EN v1.1 Address: 0x801AE364
 * EN v1.1 Size: 848b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801ae378(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9,undefined4 param_10,undefined4 param_11,int param_12,uint *param_13,
                 undefined4 param_14,undefined4 param_15,undefined4 param_16)
{
  float fVar1;
  float fVar2;
  uint uVar3;
  undefined2 *puVar4;
  undefined4 uVar5;
  undefined4 *puVar6;
  int iVar7;
  int *piVar8;
  double dVar9;
  undefined auStack_38 [4];
  float local_34;
  undefined auStack_30 [4];
  undefined4 local_2c;
  undefined4 local_28;
  undefined4 local_24;
  undefined2 local_20;
  undefined8 local_18;
  
  piVar8 = *(int **)(param_9 + 0xb8);
  local_28 = DAT_802c2a88;
  local_24 = DAT_802c2a8c;
  local_20 = DAT_802c2a90;
  if (*(char *)((int)piVar8 + 0x21) != *(char *)((int)piVar8 + 0x22)) {
    if (*(int *)(param_9 + 200) != 0) {
      param_1 = FUN_80017ac8(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                             *(int *)(param_9 + 200));
      *(undefined4 *)(param_9 + 200) = 0;
      *(undefined *)(param_9 + 0xeb) = 0;
    }
    uVar3 = FUN_80017ae8();
    if ((uVar3 & 0xff) == 0) {
      *(undefined *)((int)piVar8 + 0x22) = 0;
    }
    else {
      if (0 < *(char *)((int)piVar8 + 0x21)) {
        puVar4 = FUN_80017aa4(0x18,*(undefined2 *)
                                    ((int)&local_2c + *(char *)((int)piVar8 + 0x21) * 2 + 2));
        param_12 = -1;
        param_13 = *(uint **)(param_9 + 0x30);
        uVar5 = FUN_80017ae4(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,puVar4,
                             4,0xff,0xffffffff,param_13,param_14,param_15,param_16);
        *(undefined4 *)(param_9 + 200) = uVar5;
        *(undefined *)(param_9 + 0xeb) = 1;
      }
      *(undefined *)((int)piVar8 + 0x22) = *(undefined *)((int)piVar8 + 0x21);
    }
  }
  if (*piVar8 == 0) {
    puVar6 = ObjGroup_GetObjects(10,&local_2c);
    if (*(short *)(param_9 + 0x46) == 0x170) {
      param_12 = 0x16f;
    }
    else {
      param_12 = 0x16c;
    }
    for (iVar7 = 0; iVar7 < local_2c; iVar7 = iVar7 + 1) {
      if (param_12 == *(short *)(puVar6[iVar7] + 0x46)) {
        *piVar8 = puVar6[iVar7];
        iVar7 = local_2c;
      }
    }
  }
  if ((*(short *)(param_9 + 0x46) == 0x373) || (uVar3 = GameBit_Get(0x3a2), uVar3 != 0)) {
    iVar7 = *piVar8;
    if (*(short *)(param_9 + 0xa0) != 0x100) {
      FUN_800305f8((double)lbl_803E53E0,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                   param_9,0x100,0,param_12,param_13,param_14,param_15,param_16);
    }
    (**(code **)(**(int **)(iVar7 + 0x68) + 0x44))(iVar7,&local_34);
    local_34 = lbl_803E53E4;
    (**(code **)(**(int **)(iVar7 + 0x68) + 0x40))(iVar7,auStack_38,auStack_30);
    local_18 = (double)CONCAT44(0x43300000,(uint)DAT_803dc070);
    FUN_8002fc3c((double)local_34,(double)(float)(local_18 - DOUBLE_803e53e8));
    if (*piVar8 == 0) {
      *(undefined *)(piVar8 + 8) = 0xff;
      iVar7 = *(int *)(param_9 + 100);
      if (iVar7 != 0) {
        *(uint *)(iVar7 + 0x30) = *(uint *)(iVar7 + 0x30) & 0xffffefff;
      }
    }
    else {
      iVar7 = FUN_80017a98();
      dVar9 = (double)FUN_8001771c((float *)(*piVar8 + 0x18),(float *)(iVar7 + 0x18));
      fVar1 = (float)(dVar9 - (double)lbl_803E53F4) / lbl_803E53F8;
      fVar2 = lbl_803E53E0;
      if ((lbl_803E53E0 <= fVar1) && (fVar2 = fVar1, lbl_803E53F0 < fVar1)) {
        fVar2 = lbl_803E53F0;
      }
      *(char *)(piVar8 + 8) = (char)(int)(lbl_803E53FC * (lbl_803E53F0 - fVar2));
      iVar7 = *(int *)(param_9 + 100);
      if (iVar7 != 0) {
        *(uint *)(iVar7 + 0x30) = *(uint *)(iVar7 + 0x30) | 0x1000;
      }
    }
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801ae760
 * EN v1.0 Address: 0x801AE760
 * EN v1.0 Size: 40b
 * EN v1.1 Address: 0x801AE6B4
 * EN v1.1 Size: 132b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801ae760(int param_1)
{
  char in_r8;
  
  if (in_r8 != '\0') {
    FUN_8003b818(param_1);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801ae788
 * EN v1.0 Address: 0x801AE788
 * EN v1.0 Size: 604b
 * EN v1.1 Address: 0x801AE738
 * EN v1.1 Size: 644b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_801ae788(int param_1,undefined4 param_2,int param_3)
{
  short sVar1;
  ushort uVar2;
  int *piVar3;
  undefined4 *puVar4;
  int iVar5;
  uint uVar6;
  short *psVar7;
  
  psVar7 = *(short **)(param_1 + 0xb8);
  piVar3 = (int *)FUN_80039520(param_1,1);
  *piVar3 = (*(byte *)((int)psVar7 + 3) >> 1 & 1 ^ 1) << 8;
  if ((*(byte *)((int)psVar7 + 3) & 2) == 0) {
    sVar1 = *psVar7;
    uVar2 = (ushort)DAT_803dc070;
    *psVar7 = sVar1 - uVar2;
    if ((short)(sVar1 - uVar2) < 0) {
      *(byte *)((int)psVar7 + 3) = *(byte *)((int)psVar7 + 3) | 2;
      *psVar7 = 0x78;
    }
  }
  else {
    *(byte *)((int)psVar7 + 3) = *(byte *)((int)psVar7 + 3) & 0xfd;
  }
  if ((*(byte *)((int)psVar7 + 3) & 2) != 0) {
    DAT_803ad5b4 = lbl_803E5408;
    DAT_803ad5b8 = lbl_803E540C;
    DAT_803ad5bc = lbl_803E5410;
    (**(code **)(*DAT_803dd708 + 8))(param_1,0x133,&DAT_803ad5a8,4,0xffffffff,0);
    DAT_803ad5b4 = lbl_803E5414;
    DAT_803ad5b8 = lbl_803E540C;
    DAT_803ad5bc = lbl_803E5410;
    (**(code **)(*DAT_803dd708 + 8))(param_1,0x133,&DAT_803ad5a8,4,0xffffffff,0);
  }
  puVar4 = (undefined4 *)FUN_80039520(param_1,0);
  *puVar4 = 0x100;
  for (iVar5 = 0; iVar5 < (int)(uint)*(byte *)(param_3 + 0x8b); iVar5 = iVar5 + 1) {
    uVar6 = (uint)*(byte *)(param_3 + iVar5 + 0x81);
    switch(uVar6) {
    case 1:
      *(byte *)(psVar7 + 1) = *(byte *)(psVar7 + 1) ^ (byte)(1 << uVar6 - 1);
      break;
    case 2:
      *(byte *)(psVar7 + 1) = *(byte *)(psVar7 + 1) ^ (byte)(1 << uVar6 - 1);
      break;
    case 3:
      *(byte *)(psVar7 + 1) = *(byte *)(psVar7 + 1) ^ (byte)(1 << uVar6 - 1);
      break;
    case 4:
      *(byte *)(psVar7 + 1) = *(byte *)(psVar7 + 1) ^ (byte)(1 << uVar6 - 1);
      break;
    case 5:
      *(byte *)(psVar7 + 1) = *(byte *)(psVar7 + 1) ^ 0x70;
      break;
    case 6:
      *(byte *)((int)psVar7 + 3) = *(byte *)((int)psVar7 + 3) ^ 8;
      break;
    case 7:
      *(byte *)((int)psVar7 + 3) = *(byte *)((int)psVar7 + 3) ^ 4;
    }
  }
  return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_801ae9e4
 * EN v1.0 Address: 0x801AE9E4
 * EN v1.0 Size: 52b
 * EN v1.1 Address: 0x801AE9BC
 * EN v1.1 Size: 48b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801ae9e4(void)
{
  (**(code **)(*DAT_803dd6f8 + 0x18))();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801aea18
 * EN v1.0 Address: 0x801AEA18
 * EN v1.0 Size: 40b
 * EN v1.1 Address: 0x801AE9EC
 * EN v1.1 Size: 76b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801aea18(int param_1)
{
  char in_r8;
  
  if (in_r8 != '\0') {
    FUN_8003b818(param_1);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801aea40
 * EN v1.0 Address: 0x801AEA40
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x801AEA38
 * EN v1.1 Size: 148b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801aea40(int param_1)
{
}

/*
 * --INFO--
 *
 * Function: FUN_801aea44
 * EN v1.0 Address: 0x801AEA44
 * EN v1.0 Size: 72b
 * EN v1.1 Address: 0x801AEACC
 * EN v1.1 Size: 72b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801aea44(int param_1)
{
  uint uVar1;
  int iVar2;
  
  iVar2 = *(int *)(param_1 + 0xb8);
  uVar1 = *(uint *)(iVar2 + 4);
  if (uVar1 != 0) {
    FUN_80017814(uVar1);
  }
  uVar1 = *(uint *)(iVar2 + 8);
  if (uVar1 != 0) {
    FUN_80017814(uVar1);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801aea8c
 * EN v1.0 Address: 0x801AEA8C
 * EN v1.0 Size: 40b
 * EN v1.1 Address: 0x801AEB14
 * EN v1.1 Size: 52b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801aea8c(int param_1)
{
  char in_r8;
  
  if (in_r8 != '\0') {
    FUN_8003b818(param_1);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801aeab4
 * EN v1.0 Address: 0x801AEAB4
 * EN v1.0 Size: 580b
 * EN v1.1 Address: 0x801AEB48
 * EN v1.1 Size: 608b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801aeab4(int param_1)
{
  byte bVar1;
  ushort uVar2;
  int iVar3;
  short sVar4;
  byte *pbVar5;
  double dVar6;
  double dVar7;
  
  pbVar5 = *(byte **)(param_1 + 0xb8);
  iVar3 = *(int *)(param_1 + 0x30);
  if (iVar3 != 0) {
    sVar4 = (**(code **)(**(int **)(iVar3 + 0x68) + 0x20))(iVar3,*pbVar5);
    bVar1 = pbVar5[1];
    if (bVar1 == 1) {
      if (sVar4 == 0) {
        FUN_800178e8((double)lbl_803E5428,
                     *(int **)(*(int *)(param_1 + 0x7c) + *(char *)(param_1 + 0xad) * 4),0,-1,0,0x10
                    );
        pbVar5[2] = 0;
        pbVar5[3] = 0xb4;
        *(undefined *)(param_1 + 0x36) = 0xa4;
        pbVar5[1] = 2;
      }
    }
    else if (bVar1 == 0) {
      if (sVar4 == 1) {
        FUN_800178e8((double)lbl_803E5424,
                     *(int **)(*(int *)(param_1 + 0x7c) + *(char *)(param_1 + 0xad) * 4),0,-1,0,0x10
                    );
        *(undefined *)(param_1 + 0x36) = 0xff;
        pbVar5[1] = 1;
      }
      else {
        iVar3 = (uint)*(byte *)(param_1 + 0x36) + (uint)DAT_803dc070 * -8;
        if (iVar3 < 0) {
          iVar3 = 0;
        }
        *(char *)(param_1 + 0x36) = (char)iVar3;
      }
    }
    else if (bVar1 < 3) {
      if (sVar4 == 1) {
        pbVar5[1] = 1;
      }
      else {
        sVar4 = *(short *)(pbVar5 + 2);
        uVar2 = (ushort)DAT_803dc070;
        *(ushort *)(pbVar5 + 2) = sVar4 - uVar2;
        if ((short)(sVar4 - uVar2) < 0) {
          pbVar5[1] = 0;
        }
      }
    }
    if (*pbVar5 < 5) {
      dVar7 = (double)((float)((double)CONCAT44(0x43300000,(uint)*(byte *)(param_1 + 0x36)) -
                              DOUBLE_803e5438) / lbl_803E542C);
      dVar6 = (double)lbl_803E5420;
      if ((dVar7 <= dVar6) && (dVar6 = dVar7, dVar7 < (double)lbl_803E5430)) {
        dVar6 = (double)lbl_803E5430;
      }
      (**(code **)(**(int **)(*(int *)(param_1 + 0x30) + 0x68) + 0x28))(dVar6);
    }
    iVar3 = FUN_80039520(param_1,0);
    sVar4 = -*(short *)(iVar3 + 10) + 0x100;
    if (0x800 < sVar4) {
      sVar4 = -*(short *)(iVar3 + 10) + -0x700;
    }
    *(short *)(iVar3 + 10) = -sVar4;
    iVar3 = FUN_80039520(param_1,1);
    sVar4 = -*(short *)(iVar3 + 10) + 0xa0;
    if (0x800 < sVar4) {
      sVar4 = -*(short *)(iVar3 + 10) + -0x760;
    }
    *(short *)(iVar3 + 10) = -sVar4;
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801aecf8
 * EN v1.0 Address: 0x801AECF8
 * EN v1.0 Size: 628b
 * EN v1.1 Address: 0x801AEDA8
 * EN v1.1 Size: 420b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801aecf8(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined2 *param_9,int param_10)
{
  byte bVar1;
  int iVar2;
  int iVar3;
  undefined4 uVar4;
  undefined4 in_r8;
  undefined4 in_r9;
  undefined4 in_r10;
  int *piVar5;
  byte *pbVar6;
  undefined8 uVar7;
  
  pbVar6 = *(byte **)(param_9 + 0x5c);
  *param_9 = (short)((int)*(char *)(param_10 + 0x18) << 8);
  param_9[1] = *(undefined2 *)(param_10 + 0x1a);
  *(char *)((int)param_9 + 0xad) = (char)*(undefined2 *)(param_10 + 0x1c);
  *pbVar6 = *(byte *)(param_10 + 0x19);
  bVar1 = *pbVar6;
  if (bVar1 == 4) {
    *(float *)(param_9 + 4) = lbl_803E544C;
  }
  else if (bVar1 < 4) {
    if (bVar1 < 2) {
      *(float *)(param_9 + 4) = lbl_803E5440;
    }
    else {
      *(float *)(param_9 + 4) = lbl_803E5444;
    }
  }
  else if (bVar1 < 7) {
    *(float *)(param_9 + 4) = lbl_803E5448;
  }
  piVar5 = *(int **)(*(int *)(param_9 + 0x3e) + *(char *)((int)param_9 + 0xad) * 4);
  uVar4 = 0;
  FUN_800178e8((double)lbl_803E5430,piVar5,0,-1,0,0);
  uVar7 = FUN_800178e4((double)lbl_803E5420,piVar5,0);
  bVar1 = *pbVar6;
  if (bVar1 < 5) {
    iVar2 = FUN_80017830(0x28,0x12);
    *(int *)(pbVar6 + 4) = iVar2;
    iVar2 = (uint)bVar1 * 2;
    uVar7 = FUN_80017640(uVar7,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                         *(undefined4 *)(pbVar6 + 4),0xc,*(short *)(&DAT_80324458 + iVar2) * 0x28,
                         0x28,uVar4,in_r8,in_r9,in_r10);
    iVar3 = FUN_80017830(0x28,0x12);
    *(int *)(pbVar6 + 8) = iVar3;
    FUN_80017640(uVar7,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                 *(undefined4 *)(pbVar6 + 8),0xc,*(short *)(&DAT_80324464 + iVar2) * 0x28,0x28,uVar4
                 ,in_r8,in_r9,in_r10);
  }
  *(undefined *)(param_9 + 0x1b) = 0;
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801aef6c
 * EN v1.0 Address: 0x801AEF6C
 * EN v1.0 Size: 40b
 * EN v1.1 Address: 0x801AEF4C
 * EN v1.1 Size: 52b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801aef6c(int param_1)
{
  char in_r8;
  
  if (in_r8 != '\0') {
    FUN_8003b818(param_1);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801aef94
 * EN v1.0 Address: 0x801AEF94
 * EN v1.0 Size: 196b
 * EN v1.1 Address: 0x801AEF80
 * EN v1.1 Size: 196b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801aef94(short *param_1)
{
  int iVar1;
  
  iVar1 = *(int *)(param_1 + 0x26);
  if (*(int *)(param_1 + 0x7a) == 0) {
    param_1[1] = param_1[1] + *(short *)(iVar1 + 0x1a) * (ushort)DAT_803dc070;
  }
  else {
    *param_1 = *param_1 + *(short *)(iVar1 + 0x1a) * (ushort)DAT_803dc070;
  }
  param_1[2] = param_1[2] + *(short *)(iVar1 + 0x1c) * (ushort)DAT_803dc070;
  if (DAT_803de7c8 != 0) {
    *(undefined *)(param_1 + 0x1b) = *(undefined *)(DAT_803de7c8 + 0x36);
    FUN_80017a88((double)(*(float *)(DAT_803de7c8 + 0xc) - *(float *)(param_1 + 6)),
                 (double)(*(float *)(DAT_803de7c8 + 0x10) - *(float *)(param_1 + 8)),
                 (double)(*(float *)(DAT_803de7c8 + 0x14) - *(float *)(param_1 + 10)),(int)param_1);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801af058
 * EN v1.0 Address: 0x801AF058
 * EN v1.0 Size: 72b
 * EN v1.1 Address: 0x801AF044
 * EN v1.1 Size: 112b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801af058(undefined2 *param_1,int param_2)
{
  uint uVar1;
  
  *param_1 = (short)((int)*(char *)(param_2 + 0x18) << 8);
  uVar1 = FUN_80017760(0,1);
  *(uint *)(param_1 + 0x7a) = uVar1;
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801af0a0
 * EN v1.0 Address: 0x801AF0A0
 * EN v1.0 Size: 68b
 * EN v1.1 Address: 0x801AF0B4
 * EN v1.1 Size: 80b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801af0a0(int param_1)
{
  char in_r8;
  
  if ((in_r8 != '\0') &&
     ((*(char *)(*(int *)(param_1 + 0xb8) + 8) != '\0' || (*(char *)(param_1 + 0x36) != '\0')))) {
    FUN_8003b818(param_1);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801af0e4
 * EN v1.0 Address: 0x801AF0E4
 * EN v1.0 Size: 864b
 * EN v1.1 Address: 0x801AF104
 * EN v1.1 Size: 740b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801af0e4(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)
{
  uint uVar1;
  short *psVar2;
  undefined uVar4;
  undefined2 *puVar3;
  int iVar5;
  undefined4 in_r8;
  undefined4 in_r9;
  undefined4 in_r10;
  int *piVar6;
  int iVar7;
  undefined8 extraout_f1;
  undefined8 uVar8;
  int local_28;
  int local_24 [9];
  
  psVar2 = (short *)FUN_8028683c();
  iVar7 = *(int *)(psVar2 + 0x26);
  piVar6 = *(int **)(psVar2 + 0x5c);
  if ((*piVar6 == 0) || (piVar6[1] == 0)) {
    iVar7 = FUN_80017b00(local_24,&local_28);
    for (local_24[0] = 0; local_24[0] < local_28; local_24[0] = local_24[0] + 1) {
      iVar5 = *(int *)(iVar7 + local_24[0] * 4);
      if (*(short *)(iVar5 + 0x46) == 0x164) {
        *piVar6 = iVar5;
      }
      if (*(short *)(iVar5 + 0x46) == 0x168) {
        piVar6[1] = iVar5;
      }
    }
  }
  else {
    uVar4 = (**(code **)(**(int **)(piVar6[1] + 0x68) + 0x24))();
    *(undefined *)(piVar6 + 2) = uVar4;
    if (*(char *)(piVar6 + 2) == '\0') {
      uVar1 = (uint)*(byte *)(psVar2 + 0x1b) + (uint)DAT_803dc070 * -8;
      if ((int)uVar1 < 0) {
        uVar1 = 0;
      }
    }
    else {
      uVar1 = (uint)*(byte *)(psVar2 + 0x1b) + (uint)DAT_803dc070 * 8;
      if (0xff < uVar1) {
        uVar1 = 0xff;
      }
    }
    *(char *)(psVar2 + 0x1b) = (char)uVar1;
    if ((*(int *)(psVar2 + 0x7a) == 0) &&
       (uVar8 = extraout_f1, uVar1 = FUN_80017ae8(), (uVar1 & 0xff) != 0)) {
      iVar5 = 0;
      do {
        puVar3 = FUN_80017aa4(0x24,0x301);
        *(undefined4 *)(puVar3 + 4) = *(undefined4 *)(psVar2 + 6);
        *(undefined4 *)(puVar3 + 6) = *(undefined4 *)(psVar2 + 8);
        *(undefined4 *)(puVar3 + 8) = *(undefined4 *)(psVar2 + 10);
        uVar1 = FUN_80017760(0,0xffff);
        *(char *)(puVar3 + 0xc) = (char)uVar1;
        uVar1 = FUN_80017760(200,400);
        puVar3[0xd] = (short)uVar1;
        uVar1 = FUN_80017760(0,1);
        if (uVar1 == 0) {
          puVar3[0xd] = -puVar3[0xd];
        }
        uVar1 = FUN_80017760(200,400);
        puVar3[0xe] = (short)uVar1;
        uVar1 = FUN_80017760(0,1);
        if (uVar1 == 0) {
          puVar3[0xe] = -puVar3[0xe];
        }
        *(undefined *)(puVar3 + 2) = *(undefined *)(iVar7 + 4);
        *(undefined *)(puVar3 + 3) = *(undefined *)(iVar7 + 6);
        *(undefined *)((int)puVar3 + 5) = 1;
        *(undefined *)((int)puVar3 + 7) = 0xff;
        uVar8 = FUN_80017ae4(uVar8,param_2,param_3,param_4,param_5,param_6,param_7,param_8,puVar3,5,
                             *(undefined *)(psVar2 + 0x56),0xffffffff,*(uint **)(psVar2 + 0x18),
                             in_r8,in_r9,in_r10);
        iVar5 = iVar5 + 1;
      } while (iVar5 < 10);
      psVar2[0x7a] = 0;
      psVar2[0x7b] = 1;
    }
    iVar7 = *piVar6;
    FUN_80017a88((double)(*(float *)(iVar7 + 0xc) - *(float *)(psVar2 + 6)),
                 (double)((lbl_803E545C + *(float *)(iVar7 + 0x10)) - *(float *)(psVar2 + 8)),
                 (double)(*(float *)(iVar7 + 0x14) - *(float *)(psVar2 + 10)),(int)psVar2);
    *psVar2 = *psVar2 + (ushort)DAT_803dc070 * 0x100;
    psVar2[1] = psVar2[1] + (ushort)DAT_803dc070 * 0x20;
    psVar2[2] = psVar2[2] + (ushort)DAT_803dc070 * 0x40;
    psVar2[0x18] = 0;
    psVar2[0x19] = 0;
  }
  FUN_80286888();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801af444
 * EN v1.0 Address: 0x801AF444
 * EN v1.0 Size: 1444b
 * EN v1.1 Address: 0x801AF3E8
 * EN v1.1 Size: 1368b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801af444(void)
{
  byte bVar1;
  char cVar2;
  int iVar3;
  int iVar4;
  int iVar5;
  byte *pbVar6;
  int iVar7;
  uint uVar8;
  uint *puVar9;
  
  iVar3 = FUN_80286840();
  puVar9 = *(uint **)(iVar3 + 0xb8);
  iVar4 = FUN_80017a98();
  iVar5 = FUN_80017a90();
  pbVar6 = (byte *)(**(code **)(*DAT_803dd72c + 0x94))();
  iVar7 = (**(code **)(*DAT_803dd6d8 + 0x24))(0);
  if (iVar7 == 0) {
    if ((*(short *)(puVar9 + 3) != 0x1a) && (*(undefined2 *)(puVar9 + 3) = 0x1a, (*puVar9 & 8) != 0)
       ) {
      FUN_800067c0((int *)0x1a,1);
    }
  }
  else if ((*(short *)(puVar9 + 3) != -1) &&
          (*(undefined2 *)(puVar9 + 3) = 0xffff, (*puVar9 & 8) != 0)) {
    FUN_800067c0((int *)0x1a,0);
  }
  FUN_801d8308(puVar9,1,-1,-1,0x3a0,(int *)0x35);
  FUN_801d8308(puVar9,2,-1,-1,0xb36,(int *)0x96);
  FUN_801d8308(puVar9,8,-1,-1,0x3a1,(int *)(int)*(short *)(puVar9 + 3));
  if ((*puVar9 & 4) == 0) {
    uVar8 = GameBit_Get(0x256);
    if ((uVar8 != 0) || (uVar8 = GameBit_Get(0x1fd), uVar8 != 0)) {
      GameBit_Set(0x36e,1);
      *puVar9 = *puVar9 | 4;
    }
  }
  else {
    uVar8 = GameBit_Get(0x1fd);
    if ((uVar8 == 0) && (uVar8 = GameBit_Get(0x256), uVar8 == 0)) {
      GameBit_Set(0x36e,0);
      *puVar9 = *puVar9 & 0xfffffffb;
    }
  }
  if (iVar5 != 0) {
    FUN_80135c84(iVar5,0);
    bVar1 = *(byte *)(puVar9 + 1) >> 3 & 7;
    if (bVar1 == 2) {
      if (*pbVar6 != 0) {
        FUN_80135c84(iVar5,1);
        cVar2 = (char)*(byte *)(puVar9 + 1) >> 6;
        *(byte *)(puVar9 + 1) = (cVar2 + -1) * '@' | *(byte *)(puVar9 + 1) & 0x3f;
        if ((cVar2 == -1) && ((*(ushort *)(iVar5 + 0xb0) & 0x1000) == 0)) {
          GameBit_Set(0x386,1);
          (**(code **)(*DAT_803dd6d4 + 0x48))(*(byte *)(puVar9 + 1) >> 3 & 7,iVar3,0xffffffff);
          *(byte *)(puVar9 + 1) =
               ((*(byte *)(puVar9 + 1) >> 3 & 7) + 1) * '\b' & 0x38 | *(byte *)(puVar9 + 1) & 199;
          *(byte *)(puVar9 + 1) = *(byte *)(puVar9 + 1) & 0xf8;
          goto LAB_801af928;
        }
      }
    }
    else if (bVar1 < 2) {
      if (bVar1 == 0) {
        uVar8 = GameBit_Get(900);
        if (uVar8 != 0) {
          FUN_80135c84(iVar5,1);
          (**(code **)(*DAT_803dd6d4 + 0x48))(*(byte *)(puVar9 + 1) >> 3 & 7,iVar3,0xffffffff);
          *(byte *)(puVar9 + 1) =
               ((*(byte *)(puVar9 + 1) >> 3 & 7) + 1) * '\b' & 0x38 | *(byte *)(puVar9 + 1) & 199;
          *(byte *)(puVar9 + 1) = *(byte *)(puVar9 + 1) & 0xf8;
          goto LAB_801af928;
        }
      }
      else {
        uVar8 = GameBit_Get(0xc1);
        if ((uVar8 != 0) && ((*(ushort *)(iVar4 + 0xb0) & 0x1000) == 0)) {
          GameBit_Set(0x385,1);
          FUN_80135c84(iVar5,1);
          (**(code **)(*DAT_803dd6d4 + 0x48))(*(byte *)(puVar9 + 1) >> 3 & 7,iVar3,0xffffffff);
          *(byte *)(puVar9 + 1) =
               ((*(byte *)(puVar9 + 1) >> 3 & 7) + 1) * '\b' & 0x38 | *(byte *)(puVar9 + 1) & 199;
          *(byte *)(puVar9 + 1) = *(byte *)(puVar9 + 1) & 0xf8;
          goto LAB_801af928;
        }
      }
    }
    else if (bVar1 == 4) {
      uVar8 = GameBit_Get(0x543);
      if (uVar8 != 0) {
        FUN_80135c84(iVar5,1);
        (**(code **)(*DAT_803dd6d4 + 0x48))(*(byte *)(puVar9 + 1) >> 3 & 7,iVar3,0xffffffff);
        *(byte *)(puVar9 + 1) =
             ((*(byte *)(puVar9 + 1) >> 3 & 7) + 1) * '\b' & 0x38 | *(byte *)(puVar9 + 1) & 199;
        *(byte *)(puVar9 + 1) = *(byte *)(puVar9 + 1) & 0xf8;
        goto LAB_801af928;
      }
    }
    else if (bVar1 < 4) {
      uVar8 = GameBit_Get(0x1fd);
      if (uVar8 == 0) {
        uVar8 = GameBit_Get(0x380);
        if (uVar8 == 0) {
          if (*(char *)((int)puVar9 + 5) < '\0') {
            GameBit_Set(0x387,1);
            FUN_80135c84(iVar5,1);
            (**(code **)(*DAT_803dd6d4 + 0x48))(*(byte *)(puVar9 + 1) >> 3 & 7,iVar3,0xffffffff);
            *(byte *)(puVar9 + 1) =
                 ((*(byte *)(puVar9 + 1) >> 3 & 7) + 1) * '\b' & 0x38 | *(byte *)(puVar9 + 1) & 199;
            *(byte *)(puVar9 + 1) = *(byte *)(puVar9 + 1) & 0xf8;
            goto LAB_801af928;
          }
        }
        else {
          *(byte *)((int)puVar9 + 5) = *(byte *)((int)puVar9 + 5) & 0x7f | 0x80;
        }
      }
      else {
        GameBit_Set(0x387,1);
        *(byte *)(puVar9 + 1) =
             ((*(byte *)(puVar9 + 1) >> 3 & 7) + 1) * '\b' & 0x38 | *(byte *)(puVar9 + 1) & 199;
      }
    }
  }
  if (iVar5 != 0) {
    if ((*(ushort *)(iVar5 + 0xb0) & 0x1000) == 0) {
      puVar9[2] = (uint)((float)puVar9[2] + lbl_803DC074);
    }
    uVar8 = GameBit_Get(0x4e3);
    if ((uVar8 == 1) && (3 < *pbVar6)) {
      GameBit_Set(0x4e3,0xff);
    }
    if (lbl_803E5460 <= (float)puVar9[2]) {
      puVar9[2] = (uint)((float)puVar9[2] - lbl_803E5460);
      uVar8 = GameBit_Get(0x4e3);
      if ((uVar8 == 0xff) && (*pbVar6 < 4)) {
        GameBit_Set(0x4e3,1);
      }
    }
  }
LAB_801af928:
  FUN_8028688c();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801af9e8
 * EN v1.0 Address: 0x801AF9E8
 * EN v1.0 Size: 784b
 * EN v1.1 Address: 0x801AF940
 * EN v1.1 Size: 476b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801af9e8(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9)
{
  uint uVar1;
  int iVar2;
  char cVar3;
  undefined4 in_r7;
  undefined4 in_r8;
  undefined4 in_r9;
  undefined4 in_r10;
  uint *puVar4;
  undefined8 extraout_f1;
  undefined8 uVar5;
  undefined8 extraout_f1_00;
  
  puVar4 = *(uint **)(param_9 + 0xb8);
  *(ushort *)(param_9 + 0xb0) = *(ushort *)(param_9 + 0xb0) | 0x6000;
  uVar1 = GameBit_Get(0x36e);
  if (uVar1 != 0) {
    *puVar4 = *puVar4 & 4;
  }
  uVar1 = GameBit_Get(0x543);
  if (uVar1 == 0) {
    uVar1 = GameBit_Get(0x387);
    if (uVar1 == 0) {
      uVar1 = GameBit_Get(0x386);
      if (uVar1 == 0) {
        uVar1 = GameBit_Get(0x385);
        if (uVar1 == 0) {
          uVar1 = GameBit_Get(900);
          if (uVar1 != 0) {
            *(byte *)(puVar4 + 1) = *(byte *)(puVar4 + 1) & 199 | 8;
          }
        }
        else {
          *(byte *)(puVar4 + 1) = *(byte *)(puVar4 + 1) & 199 | 0x10;
        }
      }
      else {
        *(byte *)(puVar4 + 1) = *(byte *)(puVar4 + 1) & 199 | 0x18;
      }
    }
    else {
      *(byte *)(puVar4 + 1) = *(byte *)(puVar4 + 1) & 199 | 0x20;
    }
  }
  else {
    *(byte *)(puVar4 + 1) = *(byte *)(puVar4 + 1) & 199 | 0x28;
  }
  FUN_80080f18(&DAT_80324550,&DAT_80324518,&DAT_80324588,&DAT_803245c0);
  iVar2 = FUN_800e8b98();
  if (iVar2 == 0) {
    cVar3 = (**(code **)(*DAT_803dd72c + 0x4c))((int)*(char *)(param_9 + 0xac),0);
    uVar5 = extraout_f1_00;
    if (cVar3 == '\0') {
      uVar5 = FUN_80080f14(extraout_f1_00,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                           0x1f);
    }
    FUN_80006728(uVar5,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0,0,0x23c,0,in_r7,
                 in_r8,in_r9,in_r10);
  }
  else {
    cVar3 = (**(code **)(*DAT_803dd72c + 0x4c))((int)*(char *)(param_9 + 0xac),0);
    uVar5 = extraout_f1;
    if (cVar3 == '\0') {
      uVar5 = FUN_80080f14(extraout_f1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0x3f)
      ;
    }
    FUN_80006724(uVar5,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0,0,0x23c,0,in_r7,
                 in_r8,in_r9,in_r10);
  }
  *(undefined2 *)(puVar4 + 3) = 0;
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801afcf8
 * EN v1.0 Address: 0x801AFCF8
 * EN v1.0 Size: 376b
 * EN v1.1 Address: 0x801AFB1C
 * EN v1.1 Size: 372b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801afcf8(int param_1)
{
  char cVar1;
  int iVar2;
  uint uVar3;
  int iVar4;
  
  iVar4 = *(int *)(param_1 + 0xb8);
  cVar1 = *(char *)(param_1 + 0xac);
  if (cVar1 == 'H') {
    uVar3 = GameBit_Get(0xe1e);
    if (uVar3 == 0) {
      uVar3 = GameBit_Get(0xb72);
      if (uVar3 == 0) {
        iVar2 = (**(code **)(*DAT_803dd6d8 + 0x24))(0);
        if (iVar2 == 0) {
          if (*(int *)(iVar4 + 8) != 0x33) {
            *(undefined4 *)(iVar4 + 8) = 0x33;
            FUN_800067c0((int *)0x33,1);
          }
        }
        else if (*(int *)(iVar4 + 8) != 0x2d) {
          *(undefined4 *)(iVar4 + 8) = 0x2d;
          FUN_800067c0((int *)0x2d,1);
        }
      }
      else if (*(int *)(iVar4 + 8) != 0x95) {
        *(undefined4 *)(iVar4 + 8) = 0x95;
        FUN_800067c0((int *)0x95,1);
      }
    }
    FUN_801d8308(iVar4 + 0xc,1,-1,-1,0xe1e,(int *)0x36);
  }
  else if ((cVar1 < 'H') && ('F' < cVar1)) {
    iVar2 = (**(code **)(*DAT_803dd6d8 + 0x24))(0);
    if (iVar2 == 0) {
      if (*(int *)(iVar4 + 8) != 0x33) {
        *(undefined4 *)(iVar4 + 8) = 0x33;
        FUN_800067c0((int *)0x33,1);
      }
    }
    else if (*(int *)(iVar4 + 8) != 0x2d) {
      *(undefined4 *)(iVar4 + 8) = 0x2d;
      FUN_800067c0((int *)0x2d,1);
    }
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801afe70
 * EN v1.0 Address: 0x801AFE70
 * EN v1.0 Size: 800b
 * EN v1.1 Address: 0x801AFC90
 * EN v1.1 Size: 372b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801afe70(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9)
{
  char cVar1;
  undefined4 in_r7;
  undefined4 in_r8;
  undefined4 in_r9;
  undefined4 in_r10;
  undefined8 uVar2;
  
  cVar1 = *(char *)(param_9 + 0xac);
  if (cVar1 == 'G') {
    uVar2 = FUN_80080f18(&DAT_80324668,&DAT_80324630,&DAT_803246a0,&DAT_803246d8);
    if (*(int *)(param_9 + 0xf4) == 2) {
      FUN_80080f14(uVar2,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0x3f);
    }
    else {
      FUN_80080f14(uVar2,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0x1f);
    }
    FUN_800067c0((int *)0xc2,0);
    FUN_800067c0((int *)0xce,0);
    FUN_800067c0((int *)0xcc,0);
    FUN_800067c0((int *)0xdb,0);
    FUN_800067c0((int *)0xf2,0);
  }
  else if (cVar1 < 'G') {
    if (cVar1 == 'E') {
      uVar2 = FUN_80080f28(7,'\0');
      uVar2 = FUN_80080f14(uVar2,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0);
      uVar2 = FUN_80006728(uVar2,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0,0,0x13e,0
                           ,in_r7,in_r8,in_r9,in_r10);
      uVar2 = FUN_80006728(uVar2,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0,0,0x140,0
                           ,in_r7,in_r8,in_r9,in_r10);
      FUN_80006728(uVar2,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0,0,0x13f,0,in_r7,
                   in_r8,in_r9,in_r10);
      FUN_800067c0((int *)0xda,1);
    }
    else if ('D' < cVar1) {
      FUN_800067c0((int *)0xe1,0);
      FUN_800067c0((int *)0x96,1);
    }
  }
  else if (cVar1 == 'I') {
    FUN_800067c0((int *)0x36,1);
  }
  else if (cVar1 < 'I') {
    FUN_800067c0((int *)0xc8,0);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801b0190
 * EN v1.0 Address: 0x801B0190
 * EN v1.0 Size: 88b
 * EN v1.1 Address: 0x801AFE04
 * EN v1.1 Size: 96b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801b0190(int param_1)
{
  char cVar1;
  
  cVar1 = *(char *)(param_1 + 0xac);
  if (cVar1 < 'H') {
    if (cVar1 == 'E') {
      FUN_800067c0((int *)0xda,0);
    }
  }
  else if (cVar1 < 'J') {
    FUN_800067c0((int *)0x36,0);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801b01e8
 * EN v1.0 Address: 0x801B01E8
 * EN v1.0 Size: 308b
 * EN v1.1 Address: 0x801AFE64
 * EN v1.1 Size: 200b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801b01e8(undefined8 param_1,undefined8 param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9)
{
  int iVar1;
  char *pcVar2;
  double dVar3;
  double dVar4;
  
  pcVar2 = *(char **)(param_9 + 0xb8);
  iVar1 = FUN_80017a98();
  if (iVar1 != 0) {
    if (*pcVar2 != *(char *)(param_9 + 0xac)) {
      dVar3 = (double)*(float *)(iVar1 + 0xc);
      dVar4 = (double)*(float *)(iVar1 + 0x14);
      iVar1 = FUN_8005b024();
      if (*(char *)(param_9 + 0xac) != iVar1) {
        return;
      }
      FUN_801afe70(dVar3,dVar4,param_3,param_4,param_5,param_6,param_7,param_8,param_9);
    }
    iVar1 = FUN_8005b024();
    if (*(char *)(param_9 + 0xac) == iVar1) {
      FUN_801afcf8(param_9);
    }
    iVar1 = FUN_8005b024();
    *pcVar2 = (char)iVar1;
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801b031c
 * EN v1.0 Address: 0x801B031C
 * EN v1.0 Size: 108b
 * EN v1.1 Address: 0x801AFF2C
 * EN v1.1 Size: 108b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801b031c(int param_1)
{
  undefined *puVar1;
  int iVar2;
  
  puVar1 = *(undefined **)(param_1 + 0xb8);
  *puVar1 = 0xff;
  *(undefined4 *)(puVar1 + 4) = 0xffffffff;
  *(undefined4 *)(puVar1 + 8) = 0xffffffff;
  *(ushort *)(param_1 + 0xb0) = *(ushort *)(param_1 + 0xb0) | 0x4000;
  iVar2 = FUN_800e8b98();
  if (iVar2 == 0) {
    *(undefined4 *)(param_1 + 0xf4) = 1;
  }
  else {
    *(undefined4 *)(param_1 + 0xf4) = 2;
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801b0388
 * EN v1.0 Address: 0x801B0388
 * EN v1.0 Size: 388b
 * EN v1.1 Address: 0x801AFF98
 * EN v1.1 Size: 488b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801b0388(undefined2 *param_1,uint param_2,uint param_3)
{
  undefined4 uVar1;
  int *piVar2;
  double dVar3;
  double dVar4;
  
  piVar2 = *(int **)(param_1 + 0x5c);
  dVar4 = (double)(lbl_803E5470 *
                  (float)((double)CONCAT44(0x43300000,param_3 ^ 0x80000000) - DOUBLE_803e5480));
  uVar1 = *(undefined4 *)(*piVar2 + 0xc);
  *(undefined4 *)(param_1 + 0xc) = uVar1;
  *(undefined4 *)(param_1 + 6) = uVar1;
  uVar1 = *(undefined4 *)(*piVar2 + 0x10);
  *(undefined4 *)(param_1 + 0xe) = uVar1;
  *(undefined4 *)(param_1 + 8) = uVar1;
  uVar1 = *(undefined4 *)(*piVar2 + 0x14);
  *(undefined4 *)(param_1 + 0x10) = uVar1;
  *(undefined4 *)(param_1 + 10) = uVar1;
  *(undefined4 *)(param_1 + 0x46) = *(undefined4 *)(param_1 + 6);
  *(undefined4 *)(param_1 + 0x40) = *(undefined4 *)(param_1 + 6);
  *(undefined4 *)(param_1 + 0x48) = *(undefined4 *)(param_1 + 8);
  *(undefined4 *)(param_1 + 0x42) = *(undefined4 *)(param_1 + 8);
  *(undefined4 *)(param_1 + 0x4a) = *(undefined4 *)(param_1 + 10);
  *(undefined4 *)(param_1 + 0x44) = *(undefined4 *)(param_1 + 10);
  *param_1 = (short)((int)*(char *)(*(int *)(param_1 + 0x26) + 0x18) << 8);
  dVar3 = (double)FUN_80293f90();
  *(float *)(param_1 + 0x12) = (float)(dVar4 * -dVar3);
  *(float *)(param_1 + 0x14) =
       lbl_803E5470 * (float)((double)CONCAT44(0x43300000,param_2 ^ 0x80000000) - DOUBLE_803e5480)
  ;
  dVar3 = (double)FUN_80294964();
  *(float *)(param_1 + 0x16) = (float)(dVar4 * -dVar3);
  param_1[3] = param_1[3] & 0xbfff;
  ObjHits_EnableObject((int)param_1);
  *(byte *)(piVar2 + 4) = *(byte *)(piVar2 + 4) & 0xef;
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801b050c
 * EN v1.0 Address: 0x801B050C
 * EN v1.0 Size: 64b
 * EN v1.1 Address: 0x801B0180
 * EN v1.1 Size: 64b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801b050c(int param_1)
{
  uint uVar1;
  int iVar2;
  
  iVar2 = *(int *)(param_1 + 0xb8);
  uVar1 = *(uint *)(iVar2 + 4);
  if (uVar1 != 0) {
    FUN_80017620(uVar1);
    *(undefined4 *)(iVar2 + 4) = 0;
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801b054c
 * EN v1.0 Address: 0x801B054C
 * EN v1.0 Size: 100b
 * EN v1.1 Address: 0x801B01C0
 * EN v1.1 Size: 132b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801b054c(void)
{
  int iVar1;
  int iVar2;
  int iVar3;
  
  iVar1 = FUN_8028683c();
  iVar3 = *(int *)(iVar1 + 0xb8);
  iVar2 = *(int *)(iVar3 + 4);
  if ((iVar2 != 0) && (iVar2 = FUN_800175c4(iVar2), iVar2 != 0)) {
    FUN_8005fe14(*(int *)(iVar3 + 4));
  }
  FUN_8003b818(iVar1);
  FUN_80286888();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801b05b0
 * EN v1.0 Address: 0x801B05B0
 * EN v1.0 Size: 1132b
 * EN v1.1 Address: 0x801B0244
 * EN v1.1 Size: 876b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801b05b0(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 short *param_9)
{
  byte bVar1;
  float fVar2;
  int iVar3;
  int iVar4;
  double dVar5;
  double dVar6;
  
  fVar2 = lbl_803DC074;
  bVar1 = DAT_803dc070;
  if (param_9[0x23] == 0x1fa) {
    *(float *)(param_9 + 6) = *(float *)(param_9 + 0x12) * lbl_803DC074 + *(float *)(param_9 + 6);
    *(float *)(param_9 + 8) = *(float *)(param_9 + 0x14) * lbl_803DC074 + *(float *)(param_9 + 8);
    *(float *)(param_9 + 10) =
         *(float *)(param_9 + 0x16) * lbl_803DC074 + *(float *)(param_9 + 10);
    (**(code **)(*DAT_803dd708 + 8))(param_9,0x1f5,0,1,0xffffffff,0);
    *param_9 = *param_9 + (ushort)DAT_803dc070 * 0x374;
    param_9[1] = param_9[1] + (ushort)DAT_803dc070 * 300;
    dVar6 = (double)lbl_803E5468;
    dVar5 = (double)lbl_803DC074;
    *(float *)(param_9 + 0x14) = -(float)(dVar6 * dVar5 - (double)*(float *)(param_9 + 0x14));
    *(uint *)(param_9 + 0x7a) = *(int *)(param_9 + 0x7a) - (uint)DAT_803dc070;
    if (*(int *)(param_9 + 0x7a) < 0) {
      FUN_80017ac8(dVar5,dVar6,param_3,param_4,param_5,param_6,param_7,param_8,(int)param_9);
    }
  }
  else {
    iVar4 = *(int *)(param_9 + 0x5c);
    if ((*(byte *)(iVar4 + 0x10) & 0x10) == 0) {
      if (*(char *)(iVar4 + 0x11) != '\0') {
        *(char *)(iVar4 + 0x11) = *(char *)(iVar4 + 0x11) + -1;
      }
      *param_9 = *param_9 + (ushort)bVar1 * 0x40;
      param_9[1] = param_9[1] + (ushort)bVar1 * -0x200;
      *(float *)(param_9 + 0x14) = lbl_803E548C * fVar2 + *(float *)(param_9 + 0x14);
      dVar5 = (double)(*(float *)(param_9 + 0x14) * fVar2);
      dVar6 = (double)(*(float *)(param_9 + 0x16) * fVar2);
      FUN_80017a88((double)(*(float *)(param_9 + 0x12) * fVar2),dVar5,dVar6,(int)param_9);
      if (lbl_803E5490 <= *(float *)(param_9 + 0x14)) {
        *(byte *)(iVar4 + 0x10) = *(byte *)(iVar4 + 0x10) & 0xdf;
      }
      else if ((*(byte *)(iVar4 + 0x10) & 0x20) == 0) {
        FUN_80006824((uint)param_9,0x3dd);
        *(byte *)(iVar4 + 0x10) = *(byte *)(iVar4 + 0x10) | 0x20;
      }
      iVar3 = *(int *)(param_9 + 0x2a);
      if (iVar3 != 0) {
        *(undefined *)(iVar3 + 0x6e) = 0xb;
        *(undefined *)(iVar3 + 0x6f) = 1;
        *(undefined4 *)(iVar3 + 0x48) = 0x10;
        *(undefined4 *)(iVar3 + 0x4c) = 0x10;
        if (*(int *)(iVar3 + 0x50) != 0) {
          if (*(char *)(iVar4 + 0x11) == '\0') {
            *(undefined *)(iVar4 + 0x11) = 10;
            FUN_8008112c((double)lbl_803E5494,dVar5,dVar6,param_4,param_5,param_6,param_7,param_8,
                         param_9,1,1,0,0,0,0,0);
          }
          else {
            FUN_8008112c((double)lbl_803E5494,dVar5,dVar6,param_4,param_5,param_6,param_7,param_8,
                         param_9,0,1,0,0,0,0,0);
          }
          *(byte *)(iVar4 + 0x10) = *(byte *)(iVar4 + 0x10) | 0x10;
          param_9[3] = param_9[3] | 0x4000;
        }
        if ((*(byte *)(iVar3 + 0xad) & 1) != 0) {
          FUN_8008112c((double)lbl_803E5494,dVar5,dVar6,param_4,param_5,param_6,param_7,param_8,
                       param_9,1,1,0,0,0,0,0);
          *(byte *)(iVar4 + 0x10) = *(byte *)(iVar4 + 0x10) | 0x10;
          param_9[3] = param_9[3] | 0x4000;
          return;
        }
      }
      if (*(float *)(param_9 + 8) < *(float *)(iVar4 + 8)) {
        *(byte *)(iVar4 + 0x10) = *(byte *)(iVar4 + 0x10) | 0x10;
      }
      if ((*(byte *)(iVar4 + 0x10) & 8) == 0) {
        *(byte *)(iVar4 + 0x10) = *(byte *)(iVar4 + 0x10) | 8;
      }
      if ((*(int *)(iVar4 + 4) != 0) && (iVar3 = FUN_800175c4(*(int *)(iVar4 + 4)), iVar3 != 0)) {
        FUN_80017540(*(int *)(iVar4 + 4));
      }
    }
    else {
      ObjHits_DisableObject((int)param_9);
    }
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801b0a1c
 * EN v1.0 Address: 0x801B0A1C
 * EN v1.0 Size: 796b
 * EN v1.1 Address: 0x801B05B0
 * EN v1.1 Size: 820b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801b0a1c(undefined8 param_1,undefined8 param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 short *param_9,int param_10)
{
  uint uVar1;
  int iVar2;
  int *piVar3;
  undefined4 in_r9;
  undefined4 in_r10;
  int *piVar4;
  double dVar5;
  double dVar6;
  double dVar7;
  float local_78;
  undefined4 local_74;
  undefined4 local_70;
  ushort local_6c;
  undefined2 local_6a;
  undefined2 local_68;
  undefined4 local_50;
  uint uStack_4c;
  undefined4 local_48;
  uint uStack_44;
  undefined4 local_40;
  uint uStack_3c;
  undefined4 local_38;
  uint uStack_34;
  
  if (param_9[0x23] == 0x1fa) {
    local_78 = DAT_802c2a98;
    local_74 = DAT_802c2a9c;
    local_70 = DAT_802c2aa0;
    local_68 = 0;
    uVar1 = FUN_80017760(0xffffd120,12000);
    local_6a = (undefined2)uVar1;
    uVar1 = FUN_80017760(0,0xfffe);
    local_6c = (ushort)uVar1;
    FUN_80017748(&local_6c,&local_78);
    param_9[0x7a] = 0;
    param_9[0x7b] = 0x4b;
    *(float *)(param_9 + 0x12) = local_78;
    *(undefined4 *)(param_9 + 0x14) = local_74;
    *(undefined4 *)(param_9 + 0x16) = local_70;
    *(float *)(param_9 + 4) = *(float *)(param_9 + 4) * lbl_803E546C;
  }
  else {
    *param_9 = (short)((int)*(char *)(param_10 + 0x18) << 8);
    piVar4 = *(int **)(param_9 + 0x5c);
    uStack_4c = (int)*(short *)(param_10 + 0x1a) ^ 0x80000000;
    local_50 = 0x43300000;
    dVar7 = (double)(lbl_803E5470 *
                    (float)((double)CONCAT44(0x43300000,uStack_4c) - DOUBLE_803e5480));
    uStack_44 = (int)*(short *)(param_10 + 0x1c) ^ 0x80000000;
    local_48 = 0x43300000;
    dVar6 = (double)(lbl_803E5470 *
                    (float)((double)CONCAT44(0x43300000,uStack_44) - DOUBLE_803e5480));
    piVar4[2] = *(int *)(param_9 + 8);
    piVar4[3] = *(int *)(param_10 + 0x14);
    *(undefined4 *)(param_10 + 0x14) = 0xffffffff;
    uStack_3c = (int)*param_9 ^ 0x80000000;
    local_40 = 0x43300000;
    dVar5 = (double)FUN_80293f90();
    *(float *)(param_9 + 0x12) = (float)(dVar6 * -dVar5);
    *(float *)(param_9 + 0x14) = (float)dVar7;
    uStack_34 = (int)*param_9 ^ 0x80000000;
    local_38 = 0x43300000;
    dVar5 = (double)FUN_80294964();
    *(float *)(param_9 + 0x16) = (float)(dVar6 * -dVar5);
    if (*(int *)(param_9 + 0x2a) != 0) {
      *(undefined *)(*(int *)(param_9 + 0x2a) + 0x6a) = 0;
    }
    iVar2 = *(int *)(param_9 + 0x32);
    if (iVar2 != 0) {
      *(uint *)(iVar2 + 0x30) = *(uint *)(iVar2 + 0x30) | 0x810;
    }
    iVar2 = FUN_80017af8(piVar4[3]);
    *piVar4 = iVar2;
    *(byte *)(piVar4 + 4) = *(byte *)(piVar4 + 4) | 0x10;
    ObjHits_DisableObject((int)param_9);
    param_9[0x58] = param_9[0x58] | 0x2000;
    piVar3 = FUN_80017624((int)param_9,'\x01');
    piVar4[1] = (int)piVar3;
    if (piVar4[1] != 0) {
      FUN_800175b0(piVar4[1],2);
      FUN_8001759c(piVar4[1],0xff,0x80,0,0);
      dVar5 = (double)lbl_803E549C;
      FUN_800175d0((double)lbl_803E5498,dVar5,piVar4[1]);
      FUN_8001754c((double)lbl_803E54A0,dVar5,param_3,param_4,param_5,param_6,param_7,param_8,
                   piVar4[1],0,0xff,0x80,0,100,in_r9,in_r10);
      FUN_80017544((double)lbl_803E54A0,piVar4[1]);
    }
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801b0d38
 * EN v1.0 Address: 0x801B0D38
 * EN v1.0 Size: 148b
 * EN v1.1 Address: 0x801B08E4
 * EN v1.1 Size: 56b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801b0d38(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9,int param_10)
{
  int iVar1;
  
  if ((param_10 == 0) && (iVar1 = *(int *)(*(int *)(param_9 + 0xb8) + 8), iVar1 != 0)) {
    FUN_80017ac8(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,iVar1);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801b0dcc
 * EN v1.0 Address: 0x801B0DCC
 * EN v1.0 Size: 40b
 * EN v1.1 Address: 0x801B091C
 * EN v1.1 Size: 52b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801b0dcc(int param_1)
{
  char in_r8;
  
  if (in_r8 != '\0') {
    FUN_8003b818(param_1);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801b0df4
 * EN v1.0 Address: 0x801B0DF4
 * EN v1.0 Size: 680b
 * EN v1.1 Address: 0x801B0950
 * EN v1.1 Size: 520b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801b0df4(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9)
{
  undefined uVar1;
  float fVar2;
  uint uVar3;
  undefined2 *puVar4;
  undefined4 uVar5;
  int iVar6;
  undefined4 in_r8;
  undefined4 in_r9;
  undefined4 in_r10;
  int iVar7;
  int iVar8;
  int iVar9;
  
  iVar8 = *(int *)(param_9 + 0xb8);
  iVar9 = *(int *)(param_9 + 0x4c);
  uVar3 = GameBit_Get((int)*(short *)(iVar9 + 0x24));
  *(char *)(iVar8 + 0x1a) = (char)uVar3;
  if (*(char *)(iVar8 + 0x1b) != '\0') {
    uVar3 = GameBit_Get((int)*(short *)(iVar9 + 0x1e));
    if (uVar3 == 0) {
      *(undefined *)(iVar8 + 0x1a) = 0;
    }
    else {
      *(undefined *)(iVar8 + 0x1a) = 1;
      *(undefined *)(iVar8 + 0x1b) = 0;
      *(float *)(iVar8 + 0xc) = lbl_803E54AC;
    }
  }
  if ((*(int *)(iVar8 + 8) == 0) && (uVar3 = FUN_80017ae8(), (uVar3 & 0xff) != 0)) {
    puVar4 = FUN_80017aa4(0x24,0x18d);
    *(undefined *)(puVar4 + 1) = 9;
    *(undefined *)(puVar4 + 2) = 2;
    *(undefined *)(puVar4 + 3) = 0xff;
    *(undefined *)((int)puVar4 + 5) = 4;
    *(undefined *)((int)puVar4 + 7) = 0x50;
    *(undefined4 *)(puVar4 + 4) = *(undefined4 *)(param_9 + 0xc);
    *(undefined4 *)(puVar4 + 6) = *(undefined4 *)(param_9 + 0x10);
    *(undefined4 *)(puVar4 + 8) = *(undefined4 *)(param_9 + 0x14);
    *(undefined *)(puVar4 + 0xc) = *(undefined *)(iVar9 + 0x1c);
    puVar4[0xd] = (ushort)*(byte *)(iVar9 + 0x1a);
    puVar4[0xe] = (ushort)*(byte *)(iVar9 + 0x1b);
    *(undefined4 *)(puVar4 + 10) = *(undefined4 *)(iVar9 + 0x14);
    uVar5 = FUN_80017ae4(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,puVar4,5,
                         *(undefined *)(param_9 + 0xac),0xffffffff,(uint *)0x0,in_r8,in_r9,in_r10);
    *(undefined4 *)(iVar8 + 8) = uVar5;
  }
  iVar7 = *(int *)(iVar8 + 8);
  fVar2 = *(float *)(iVar8 + 0xc) - lbl_803DC074;
  *(float *)(iVar8 + 0xc) = fVar2;
  if ((fVar2 <= lbl_803E54AC) &&
     (iVar6 = (**(code **)(**(int **)(iVar7 + 0x68) + 0x24))(iVar7), iVar6 != 0)) {
    if (*(char *)(iVar8 + 0x1a) != '\0') {
      uVar3 = GameBit_Get((int)*(short *)(iVar9 + 0x1e));
      if ((uVar3 == 0) || (*(char *)(iVar8 + 0x18) != '\0')) {
        uVar1 = *(undefined *)(iVar9 + 0x1a);
      }
      else {
        uVar1 = *(undefined *)(iVar9 + 0x20);
        *(undefined *)(iVar8 + 0x18) = 1;
      }
      (**(code **)(**(int **)(iVar7 + 0x68) + 0x20))(iVar7,uVar1,*(undefined *)(iVar9 + 0x1b));
    }
    uVar3 = FUN_80017760(0,0x3c);
    *(float *)(iVar8 + 0xc) =
         *(float *)(iVar8 + 0x10) +
         (float)((double)CONCAT44(0x43300000,uVar3 ^ 0x80000000) - DOUBLE_803e54b0);
  }
  return;
}


/* Trivial 4b 0-arg blr leaves. */
void imicepillar_hitDetect(void) {}
void imicepillar_update(void) {}
void imicepillar_init(void) {}
void imicepillar_release(void) {}
void imicepillar_initialise(void) {}
void imanimspacecraft_modelMtxFn(void) {}
void imanimspacecraft_hitDetect(void) {}
void imanimspacecraft_release(void) {}
void imanimspacecraft_initialise(void) {}
void imspacethruster_hitDetect(void) {}
void imspacethruster_release(void) {}
void imspacethruster_initialise(void) {}
void imspacering_free(void) {}
void imspacering_hitDetect(void) {}
void imspacering_release(void) {}
void imspacering_initialise(void) {}
void imspaceringgen_hitDetect(void) {}
void imspaceringgen_release(void) {}
void imspaceringgen_initialise(void) {}
void lavaball1be_hitDetect(void) {}
void lavaball1be_release(void) {}
void lavaball1be_initialise(void) {}
void lavaball1bf_hitDetect(void) {}
void lavaball1bf_release(void) {}
void lavaball1bf_initialise(void) {}

/* 8b "li r3, N; blr" returners. */
int imanimspacecraft_getExtraSize(void) { return 0x4; }
int imanimspacecraft_func08(void) { return 0x0; }
int imspacethruster_getExtraSize(void) { return 0xc; }
int imspacethruster_func08(void) { return 0x0; }
int imspacering_getExtraSize(void) { return 0x0; }
int imspacering_func08(void) { return 0x0; }
int imspaceringgen_getExtraSize(void) { return 0xc; }
int imspaceringgen_func08(void) { return 0x0; }
int linkb_levcontrol_getExtraSize(void) { return 0x10; }
int link_levcontrol_getExtraSize(void) { return 0x10; }
int lavaball1bf_getExtraSize(void) { return 0x1c; }
int lavaball1bf_func08(void) { return 0x0; }
int dimlogfire_getExtraSize(void) { return 0x24; }
int dimlogfire_func08(void) { return 0x1; }

/* Pattern wrappers. */
extern u32 lbl_803DDB48;
void imspaceringgen_free(void) { lbl_803DDB48 = 0x0; }

/* render-with-objRenderFn_8003b8f4 pattern. */
extern f32 lbl_803E4780;
extern void objRenderFn_8003b8f4(f32);
extern f32 lbl_803E4788;
extern f32 lbl_803E47B8;
extern f32 lbl_803E4810;
#pragma peephole off
void imanimspacecraft_render(int p1, int p2, int p3, int p4, int p5, s8 visible) { s32 v = visible; if (v != 0) objRenderFn_8003b8f4(lbl_803E4780); }
void imspacethruster_render(int p1, int p2, int p3, int p4, int p5, s8 visible) { s32 v = visible; if (v != 0) objRenderFn_8003b8f4(lbl_803E4788); }
void imspacering_render(int p1, int p2, int p3, int p4, int p5, s8 visible) { s32 v = visible; if (v != 0) objRenderFn_8003b8f4(lbl_803E47B8); }
void lavaball1bf_render(int p1, int p2, int p3, int p4, int p5, s8 visible) { s32 v = visible; if (v != 0) objRenderFn_8003b8f4(lbl_803E4810); }
#pragma peephole reset

/* if (o->_X == K) return A; else return B;  pattern. */
#pragma peephole off
#pragma scheduling off
#pragma peephole off
int lavaball1be_getExtraSize(int *obj) { if (*(s16*)((char*)obj + 0x46) == 0x1fa) return 0x0; return 0x14; }
int lavaball1be_func08(int *obj) { if (*(s16*)((char*)obj + 0x46) == 0x1fa) return 0x0; return 0x2; }
#pragma peephole reset
#pragma scheduling reset
#pragma peephole reset

/* chained byte mask. */
u32 imanimspacecraft_func0B(int *obj) { return *((u8*)((int**)obj)[0xb8/4] + 0x3) & 0x4; }
u32 lavaball1be_func11(int *obj) { return *((u8*)((int**)obj)[0xb8/4] + 0x10) & 0x10; }
