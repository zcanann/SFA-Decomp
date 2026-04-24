// Function: FUN_801461dc
// Entry: 801461dc
// Size: 480 bytes

void FUN_801461dc(int param_1,int param_2)

{
  int iVar1;
  int iVar2;
  int iVar3;
  
  iVar1 = *(int *)(param_1 + 0xb8);
  FUN_8004b594(iVar1 + 0x538);
  FUN_8004b594(iVar1 + 0x568);
  FUN_8004b594(iVar1 + 0x598);
  FUN_8004b594(iVar1 + 0x5c8);
  FUN_8004b594(iVar1 + 0x5f8);
  FUN_8004b594(iVar1 + 0x628);
  FUN_8004b594(iVar1 + 0x658);
  FUN_8004b594(iVar1 + 0x688);
  FUN_8004b594(iVar1 + 0x6b8);
  FUN_80036fa4(param_1,1);
  (**(code **)(*DAT_803dca78 + 0x14))(param_1);
  if ((param_2 == 0) && ((*(uint *)(iVar1 + 0x54) & 0x800) != 0)) {
    *(uint *)(iVar1 + 0x54) = *(uint *)(iVar1 + 0x54) & 0xfffff7ff;
    *(uint *)(iVar1 + 0x54) = *(uint *)(iVar1 + 0x54) | 0x1000;
    iVar3 = 0;
    iVar2 = iVar1;
    do {
      FUN_8017804c(*(undefined4 *)(iVar2 + 0x700));
      iVar2 = iVar2 + 4;
      iVar3 = iVar3 + 1;
    } while (iVar3 < 7);
    FUN_8000db90(param_1,0x3dc);
    iVar2 = *(int *)(param_1 + 0xb8);
    if (((*(byte *)(iVar2 + 0x58) >> 6 & 1) == 0) &&
       (((0x2f < *(short *)(param_1 + 0xa0) || (*(short *)(param_1 + 0xa0) < 0x29)) &&
        (iVar3 = FUN_8000b578(param_1,0x10), iVar3 == 0)))) {
      FUN_800393f8(param_1,iVar2 + 0x3a8,0x29d,0,0xffffffff,0);
    }
  }
  FUN_800dd640();
  FUN_801389e0(param_1,iVar1,iVar1 + 0x7a8);
  FUN_801389e0(param_1,iVar1,iVar1 + 0x7b0);
  FUN_801389e0(param_1,iVar1,iVar1 + 0x7b8);
  if (*(int *)(iVar1 + 0x7cc) != 0) {
    FUN_80037cb0(param_1);
    FUN_8002cbc4(*(undefined4 *)(iVar1 + 0x7cc));
  }
  if ((*(char *)(iVar1 + 0x58) < '\0') && (DAT_803dda48 != 0)) {
    FUN_8002cbc4();
    DAT_803dda48 = 0;
  }
  return;
}

