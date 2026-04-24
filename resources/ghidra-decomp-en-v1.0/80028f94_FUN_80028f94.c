// Function: FUN_80028f94
// Entry: 80028f94
// Size: 520 bytes

void FUN_80028f94(int param_1)

{
  int iVar1;
  int iVar2;
  
  if (*(int *)(param_1 + 0x58) != 0) {
    *(int *)(param_1 + 0x58) = param_1 + *(int *)(param_1 + 0x58);
  }
  if (*(int *)(param_1 + 0x3c) != 0) {
    *(int *)(param_1 + 0x3c) = param_1 + *(int *)(param_1 + 0x3c);
    if (*(int *)(param_1 + 0x18) != 0) {
      *(int *)(param_1 + 0x18) = param_1 + *(int *)(param_1 + 0x18);
    }
    if (*(int *)(param_1 + 0x1c) != 0) {
      *(int *)(param_1 + 0x1c) = param_1 + *(int *)(param_1 + 0x1c);
    }
    if (*(int *)(param_1 + 0x40) != 0) {
      *(int *)(param_1 + 0x40) = param_1 + *(int *)(param_1 + 0x40);
    }
  }
  if (*(int *)(param_1 + 0x54) != 0) {
    *(int *)(param_1 + 0x54) = param_1 + *(int *)(param_1 + 0x54);
  }
  if (*(int *)(param_1 + 0x20) != 0) {
    *(int *)(param_1 + 0x20) = param_1 + *(int *)(param_1 + 0x20);
  }
  *(int *)(param_1 + 0x28) = param_1 + *(int *)(param_1 + 0x28);
  if (*(int *)(param_1 + 0x2c) != 0) {
    *(int *)(param_1 + 0x2c) = param_1 + *(int *)(param_1 + 0x2c);
  }
  if (*(int *)(param_1 + 0x30) != 0) {
    *(int *)(param_1 + 0x30) = param_1 + *(int *)(param_1 + 0x30);
  }
  if (*(int *)(param_1 + 0x34) != 0) {
    *(int *)(param_1 + 0x34) = param_1 + *(int *)(param_1 + 0x34);
  }
  if (*(int *)(param_1 + 0xd4) != 0) {
    *(int *)(param_1 + 0xd4) = param_1 + *(int *)(param_1 + 0xd4);
  }
  if (*(int *)(param_1 + 0xd0) != 0) {
    *(int *)(param_1 + 0xd0) = param_1 + *(int *)(param_1 + 0xd0);
  }
  if (*(int *)(param_1 + 0xdc) != 0) {
    *(int *)(param_1 + 0xdc) = param_1 + *(int *)(param_1 + 0xdc);
  }
  if (*(int *)(param_1 + 0xa4) != 0) {
    *(int *)(param_1 + 0xa4) = param_1 + *(int *)(param_1 + 0xa4);
  }
  if (*(int *)(param_1 + 0xa8) != 0) {
    *(int *)(param_1 + 0xa8) = param_1 + *(int *)(param_1 + 0xa8);
  }
  if (*(int *)(param_1 + 200) != 0) {
    *(int *)(param_1 + 200) = param_1 + *(int *)(param_1 + 200);
  }
  if (*(int *)(param_1 + 0xcc) != 0) {
    *(int *)(param_1 + 0xcc) = param_1 + *(int *)(param_1 + 0xcc);
  }
  if (*(int *)(param_1 + 0x38) != 0) {
    *(int *)(param_1 + 0x38) = param_1 + *(int *)(param_1 + 0x38);
  }
  iVar1 = 0;
  for (iVar2 = 0; iVar2 < (int)((uint)*(byte *)(param_1 + 0xf5) + (uint)*(byte *)(param_1 + 0xf6));
      iVar2 = iVar2 + 1) {
    *(int *)(*(int *)(param_1 + 0xd0) + iVar1) =
         param_1 + *(int *)(*(int *)(param_1 + 0xd0) + iVar1);
    iVar1 = iVar1 + 0x1c;
  }
  iVar1 = 0;
  for (iVar2 = 0; iVar2 < (int)(uint)*(byte *)(param_1 + 0xf9); iVar2 = iVar2 + 1) {
    *(int *)(*(int *)(param_1 + 0xdc) + iVar1) =
         param_1 + *(int *)(*(int *)(param_1 + 0xdc) + iVar1);
    iVar1 = iVar1 + 4;
  }
  if (*(int *)(param_1 + 0x5c) != 0) {
    *(int *)(param_1 + 0x5c) = param_1 + *(int *)(param_1 + 0x5c);
  }
  if (*(int *)(param_1 + 0x60) == 0) {
    return;
  }
  *(int *)(param_1 + 0x60) = param_1 + *(int *)(param_1 + 0x60);
  return;
}

