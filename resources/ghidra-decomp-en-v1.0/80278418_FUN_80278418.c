// Function: FUN_80278418
// Entry: 80278418
// Size: 328 bytes

void FUN_80278418(uint param_1)

{
  int iVar1;
  int iVar2;
  uint uVar3;
  int iVar4;
  bool bVar5;
  
  iVar1 = DAT_803de2d8;
  while (iVar2 = DAT_803de2d4, iVar1 != 0) {
    uVar3 = *(uint *)(iVar1 + 0x9c);
    iVar4 = *(int *)(iVar1 + 0x98);
    if (DAT_803de2e0 < (uint)(DAT_803de2e4 < uVar3) + iVar4) break;
    iVar2 = *(int *)(iVar1 + 0x44);
    FUN_80278990(iVar1);
    *(uint *)(iVar1 + 0xa4) = uVar3;
    *(int *)(iVar1 + 0xa0) = iVar4;
    iVar1 = iVar2;
  }
  for (; iVar2 != 0; iVar2 = *(int *)(iVar2 + 0x3c)) {
    if (*(char *)(iVar2 + 0x68) == '\0') {
      bVar5 = false;
    }
    else {
      bVar5 = *(int *)(iVar2 + 0x54) != 0;
    }
    if ((((bVar5) && ((*(uint *)(iVar2 + 0x118) & 0x20) == 0)) &&
        (iVar1 = FUN_80283254(*(uint *)(iVar2 + 0xf4) & 0xff), iVar1 == 0)) &&
       ((*(char *)(iVar2 + 0x68) != '\0' && (*(int *)(iVar2 + 0x54) != 0)))) {
      *(undefined4 *)(iVar2 + 0x38) = *(undefined4 *)(iVar2 + 0x60);
      *(undefined4 *)(iVar2 + 0x34) = *(undefined4 *)(iVar2 + 0x54);
      *(undefined4 *)(iVar2 + 0x54) = 0;
      FUN_80278990(iVar2);
    }
    FUN_80276f0c(iVar2);
  }
  DAT_803de2e0 = DAT_803de2e0 + CARRY4(DAT_803de2e4,param_1);
  DAT_803de2e4 = DAT_803de2e4 + param_1;
  return;
}

