// Function: FUN_8022980c
// Entry: 8022980c
// Size: 392 bytes

void FUN_8022980c(void)

{
  undefined2 *puVar1;
  int iVar2;
  int iVar3;
  int iVar4;
  int iVar5;
  undefined4 *puVar6;
  undefined8 uVar7;
  
  uVar7 = FUN_802860d8();
  puVar1 = (undefined2 *)((ulonglong)uVar7 >> 0x20);
  iVar3 = (int)uVar7;
  puVar6 = *(undefined4 **)(puVar1 + 0x5c);
  *puVar1 = (short)((int)*(char *)(iVar3 + 0x18) << 8);
  *(undefined *)((int)puVar1 + 0xad) = *(undefined *)(iVar3 + 0x19);
  if (*(char *)(*(int *)(puVar1 + 0x28) + 0x55) <= *(char *)((int)puVar1 + 0xad)) {
    *(undefined *)((int)puVar1 + 0xad) = 0;
  }
  if (*(char *)((int)puVar1 + 0xad) == '\0') {
    puVar6[4] = &DAT_803dc3b8;
    puVar6[3] = &DAT_8032b348;
  }
  else {
    puVar6[4] = &DAT_803dc3c0;
    puVar6[3] = &DAT_8032b354;
  }
  iVar4 = 0;
  iVar5 = 0;
  do {
    iVar2 = FUN_8001ffb4((int)*(short *)(puVar6[4] + iVar5));
    if (iVar2 != 0) {
      *(byte *)(puVar6 + 2) = *(byte *)(puVar6 + 2) | (byte)(1 << iVar4);
    }
    iVar5 = iVar5 + 2;
    iVar4 = iVar4 + 1;
  } while (iVar4 < 3);
  iVar3 = FUN_8001ffb4((int)*(short *)(iVar3 + 0x1e));
  if (iVar3 != 0) {
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
  *(code **)(puVar1 + 0x5e) = FUN_802294cc;
  FUN_802293f8(puVar1,*(undefined *)(puVar6 + 2));
  FUN_80286124();
  return;
}

