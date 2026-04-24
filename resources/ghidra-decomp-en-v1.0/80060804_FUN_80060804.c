// Function: FUN_80060804
// Entry: 80060804
// Size: 240 bytes

void FUN_80060804(int param_1)

{
  int iVar1;
  int iVar2;
  
  if (*(int *)(param_1 + 0x54) != 0) {
    *(int *)(param_1 + 0x54) = param_1 + *(int *)(param_1 + 0x54);
  }
  if (*(int *)(param_1 + 0x4c) != 0) {
    *(int *)(param_1 + 0x4c) = param_1 + *(int *)(param_1 + 0x4c);
  }
  if (*(int *)(param_1 + 0x50) != 0) {
    *(int *)(param_1 + 0x50) = param_1 + *(int *)(param_1 + 0x50);
  }
  *(int *)(param_1 + 0x58) = param_1 + *(int *)(param_1 + 0x58);
  *(int *)(param_1 + 0x5c) = param_1 + *(int *)(param_1 + 0x5c);
  *(int *)(param_1 + 0x60) = param_1 + *(int *)(param_1 + 0x60);
  if (*(int *)(param_1 + 0x78) != 0) {
    *(int *)(param_1 + 0x78) = param_1 + *(int *)(param_1 + 0x78);
  }
  if (*(int *)(param_1 + 0x7c) != 0) {
    *(int *)(param_1 + 0x7c) = param_1 + *(int *)(param_1 + 0x7c);
  }
  if (*(int *)(param_1 + 0x80) != 0) {
    *(int *)(param_1 + 0x80) = param_1 + *(int *)(param_1 + 0x80);
  }
  *(int *)(param_1 + 0x68) = param_1 + *(int *)(param_1 + 0x68);
  if (*(int *)(param_1 + 100) != 0) {
    *(int *)(param_1 + 100) = param_1 + *(int *)(param_1 + 100);
  }
  iVar1 = 0;
  for (iVar2 = 0; iVar2 < (int)(uint)*(byte *)(param_1 + 0xa1); iVar2 = iVar2 + 1) {
    *(int *)(*(int *)(param_1 + 0x68) + iVar1) =
         param_1 + *(int *)(*(int *)(param_1 + 0x68) + iVar1);
    iVar1 = iVar1 + 0x1c;
  }
  return;
}

