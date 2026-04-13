// Function: FUN_80229ed0
// Entry: 80229ed0
// Size: 392 bytes

void FUN_80229ed0(void)

{
  undefined2 *puVar1;
  uint uVar2;
  int iVar3;
  int iVar4;
  int iVar5;
  undefined4 *puVar6;
  undefined8 uVar7;
  
  uVar7 = FUN_8028683c();
  puVar1 = (undefined2 *)((ulonglong)uVar7 >> 0x20);
  iVar3 = (int)uVar7;
  puVar6 = *(undefined4 **)(puVar1 + 0x5c);
  *puVar1 = (short)((int)*(char *)(iVar3 + 0x18) << 8);
  *(undefined *)((int)puVar1 + 0xad) = *(undefined *)(iVar3 + 0x19);
  if (*(char *)(*(int *)(puVar1 + 0x28) + 0x55) <= *(char *)((int)puVar1 + 0xad)) {
    *(undefined *)((int)puVar1 + 0xad) = 0;
  }
  if (*(char *)((int)puVar1 + 0xad) == '\0') {
    puVar6[4] = &DAT_803dd020;
    puVar6[3] = &DAT_8032bfa0;
  }
  else {
    puVar6[4] = &DAT_803dd028;
    puVar6[3] = &DAT_8032bfac;
  }
  iVar4 = 0;
  iVar5 = 0;
  do {
    uVar2 = FUN_80020078((int)*(short *)(puVar6[4] + iVar5));
    if (uVar2 != 0) {
      *(byte *)(puVar6 + 2) = *(byte *)(puVar6 + 2) | (byte)(1 << iVar4);
    }
    iVar5 = iVar5 + 2;
    iVar4 = iVar4 + 1;
  } while (iVar4 < 3);
  uVar2 = FUN_80020078((int)*(short *)(iVar3 + 0x1e));
  if (uVar2 != 0) {
    *(undefined *)(puVar6 + 2) = 7;
    *(byte *)((int)puVar6 + 9) = *(byte *)((int)puVar6 + 9) | 1;
  }
  if ((*(byte *)(puVar6 + 2) & 2) == 0) {
    if ((*(byte *)(puVar6 + 2) & 1) == 0) {
      *puVar6 = *(undefined4 *)puVar6[3];
    }
    else {
      *puVar6 = *(undefined4 *)(puVar6[3] + 4);
    }
  }
  else {
    *puVar6 = *(undefined4 *)(puVar6[3] + 8);
  }
  puVar6[1] = *puVar6;
  *(code **)(puVar1 + 0x5e) = FUN_80229b90;
  FUN_80229abc();
  FUN_80286888();
  return;
}

