// Function: FUN_801b98fc
// Entry: 801b98fc
// Size: 644 bytes

/* WARNING: Removing unreachable block (ram,0x801b99ec) */

void FUN_801b98fc(int param_1)

{
  byte bVar1;
  undefined4 uVar2;
  int iVar3;
  char *pcVar4;
  undefined auStack24 [20];
  
  if (*(int *)(param_1 + 0xf4) != 0) {
    if (*(int *)(param_1 + 0xf4) == 2) {
      FUN_80008b74(0,0,0x163,0);
      FUN_80008b74(0,0,0x166,0);
      FUN_80008b74(0,0,0x165,0);
      FUN_80008b74(0,0,0x164,0);
    }
    else {
      FUN_80008cbc(0,0,0x163,0);
      FUN_80008cbc(0,0,0x166,0);
      FUN_80008cbc(0,0,0x165,0);
      FUN_80008cbc(0,0,0x164,0);
    }
    *(undefined4 *)(param_1 + 0xf4) = 0;
  }
  pcVar4 = *(char **)(param_1 + 0xb8);
  if (((pcVar4[4] != '\x01') && (pcVar4[4] == '\0')) && (iVar3 = FUN_8001ffb4(0xacd), iVar3 != 0)) {
    FUN_800200e8(0xcc3,1);
    pcVar4[4] = '\x01';
  }
  bVar1 = pcVar4[3];
  if ((uint)bVar1 != (uint)(byte)(&DAT_803dbf28)[*pcVar4]) {
    if ((int)((uint)bVar1 - (uint)(byte)(&DAT_803dbf28)[*pcVar4]) < 1) {
      pcVar4[3] = bVar1 + 1;
    }
    else {
      pcVar4[3] = bVar1 - 1;
    }
    FUN_8004c1e4((double)FLOAT_803e4b90,pcVar4[3]);
  }
  uVar2 = FUN_8002b9ec();
  iVar3 = FUN_802966d4(uVar2,auStack24);
  if (iVar3 == 0) {
    if (((*(uint *)(pcVar4 + 8) & 2) != 0) && (*(int *)(pcVar4 + 0xc) != 0xd7)) {
      FUN_8000a518(*(int *)(pcVar4 + 0xc),0);
      *(undefined4 *)(pcVar4 + 0xc) = 0xd7;
      FUN_8000a518(0xd7,1);
    }
  }
  else if (((*(uint *)(pcVar4 + 8) & 2) != 0) && (*(int *)(pcVar4 + 0xc) != 0xe0)) {
    FUN_8000a518(*(int *)(pcVar4 + 0xc),0);
    *(undefined4 *)(pcVar4 + 0xc) = 0xe0;
    FUN_8000a518(0xe0,1);
  }
  FUN_801d7ed4(pcVar4 + 8,1,0xffffffff,0xffffffff,0xd99,0xde);
  FUN_801d7ed4(pcVar4 + 8,2,0xffffffff,0xffffffff,0xda5,*(undefined4 *)(pcVar4 + 0xc));
  FUN_801d7ed4(pcVar4 + 8,8,0xffffffff,0xffffffff,0xf04,0x96);
  FUN_801d8060(pcVar4 + 8,0x10,0xffffffff,0xffffffff,0xf04,0x2c);
  FUN_801d7ed4(pcVar4 + 8,4,0xffffffff,0xffffffff,0xcbb,0xc4);
  return;
}

