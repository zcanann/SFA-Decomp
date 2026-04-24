// Function: FUN_801b9eb0
// Entry: 801b9eb0
// Size: 644 bytes

/* WARNING: Removing unreachable block (ram,0x801b9fa0) */

void FUN_801b9eb0(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9)

{
  byte bVar1;
  int iVar2;
  uint uVar3;
  undefined4 in_r7;
  undefined4 in_r8;
  undefined4 in_r9;
  undefined4 in_r10;
  char *pcVar4;
  undefined8 uVar5;
  undefined4 auStack_18 [5];
  
  if (*(int *)(param_9 + 0xf4) != 0) {
    if (*(int *)(param_9 + 0xf4) == 2) {
      uVar5 = FUN_80008b74(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0,0,0x163
                           ,0,in_r7,in_r8,in_r9,in_r10);
      uVar5 = FUN_80008b74(uVar5,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0,0,0x166,0
                           ,in_r7,in_r8,in_r9,in_r10);
      uVar5 = FUN_80008b74(uVar5,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0,0,0x165,0
                           ,in_r7,in_r8,in_r9,in_r10);
      FUN_80008b74(uVar5,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0,0,0x164,0,in_r7,
                   in_r8,in_r9,in_r10);
    }
    else {
      uVar5 = FUN_80008cbc(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0,0,0x163
                           ,0,in_r7,in_r8,in_r9,in_r10);
      uVar5 = FUN_80008cbc(uVar5,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0,0,0x166,0
                           ,in_r7,in_r8,in_r9,in_r10);
      uVar5 = FUN_80008cbc(uVar5,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0,0,0x165,0
                           ,in_r7,in_r8,in_r9,in_r10);
      FUN_80008cbc(uVar5,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0,0,0x164,0,in_r7,
                   in_r8,in_r9,in_r10);
    }
    *(undefined4 *)(param_9 + 0xf4) = 0;
  }
  pcVar4 = *(char **)(param_9 + 0xb8);
  if (((pcVar4[4] != '\x01') && (pcVar4[4] == '\0')) && (uVar3 = FUN_80020078(0xacd), uVar3 != 0)) {
    FUN_800201ac(0xcc3,1);
    pcVar4[4] = '\x01';
  }
  bVar1 = pcVar4[3];
  if ((uint)bVar1 != (uint)(byte)(&DAT_803dcb90)[*pcVar4]) {
    if ((int)((uint)bVar1 - (uint)(byte)(&DAT_803dcb90)[*pcVar4]) < 1) {
      pcVar4[3] = bVar1 + 1;
    }
    else {
      pcVar4[3] = bVar1 - 1;
    }
    FUN_8004c360((double)FLOAT_803e5828,pcVar4[3]);
  }
  iVar2 = FUN_8002bac4();
  uVar3 = FUN_80296e34(iVar2,auStack_18);
  if (uVar3 == 0) {
    if (((*(uint *)(pcVar4 + 8) & 2) != 0) && (*(int **)(pcVar4 + 0xc) != (int *)0xd7)) {
      FUN_8000a538(*(int **)(pcVar4 + 0xc),0);
      pcVar4[0xc] = '\0';
      pcVar4[0xd] = '\0';
      pcVar4[0xe] = '\0';
      pcVar4[0xf] = -0x29;
      FUN_8000a538((int *)0xd7,1);
    }
  }
  else if (((*(uint *)(pcVar4 + 8) & 2) != 0) && (*(int **)(pcVar4 + 0xc) != (int *)0xe0)) {
    FUN_8000a538(*(int **)(pcVar4 + 0xc),0);
    pcVar4[0xc] = '\0';
    pcVar4[0xd] = '\0';
    pcVar4[0xe] = '\0';
    pcVar4[0xf] = -0x20;
    FUN_8000a538((int *)0xe0,1);
  }
  FUN_801d84c4(pcVar4 + 8,1,-1,-1,0xd99,(int *)0xde);
  FUN_801d84c4(pcVar4 + 8,2,-1,-1,0xda5,*(int **)(pcVar4 + 0xc));
  FUN_801d84c4(pcVar4 + 8,8,-1,-1,0xf04,(int *)0x96);
  FUN_801d8650(pcVar4 + 8,0x10,-1,-1,0xf04,(int *)0x2c);
  FUN_801d84c4(pcVar4 + 8,4,-1,-1,0xcbb,(int *)0xc4);
  return;
}

