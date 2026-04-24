// Function: FUN_801a1380
// Entry: 801a1380
// Size: 244 bytes

void FUN_801a1380(int param_1,char param_2)

{
  int iVar1;
  int iVar2;
  
  iVar2 = *(int *)(param_1 + 0xb8);
  iVar1 = *(int *)(param_1 + 0x54);
  if (param_2 == '\0') {
    *(undefined *)(iVar1 + 0x6a) = *(undefined *)(*(int *)(param_1 + 0x50) + 99);
    *(undefined *)(iVar1 + 0x6b) = *(undefined *)(*(int *)(param_1 + 0x50) + 100);
    *(byte *)(iVar2 + 0x4a) = *(byte *)(iVar2 + 0x4a) & 0x7f;
    *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) & 0xf7;
    FUN_80035f54(param_1,0x400);
    *(byte *)(iVar2 + 0x49) = *(byte *)(iVar2 + 0x49) | 1;
  }
  else {
    *(undefined *)(iVar1 + 0x6a) = 1;
    *(undefined *)(iVar1 + 0x6b) = 1;
    *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) | 8;
    *(byte *)(iVar2 + 0x4a) = *(byte *)(iVar2 + 0x4a) & 0x7f | 0x80;
    *(byte *)(iVar2 + 0x49) = *(byte *)(iVar2 + 0x49) & 0xfd;
    FUN_80035f6c(param_1,0x480);
    FUN_80035f28(param_1,1);
    FUN_80036018(param_1);
    FUN_80035f9c(param_1);
  }
  return;
}

