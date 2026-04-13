// Function: FUN_80145e08
// Entry: 80145e08
// Size: 240 bytes

void FUN_80145e08(int param_1,int param_2,undefined param_3,int param_4)

{
  int iVar1;
  int iVar2;
  int iVar3;
  uint uVar4;
  
  iVar1 = *(int *)(param_1 + 0xb8);
  if (*(char *)(iVar1 + 0x798) == '\n') {
    FUN_80148fa0();
  }
  else {
    *(byte *)(iVar1 + 0xb) = *(byte *)(iVar1 + 0xb) | (byte)(1 << param_4);
    iVar3 = 0;
    iVar2 = iVar1;
    for (uVar4 = (uint)*(byte *)(iVar1 + 0x798); uVar4 != 0; uVar4 = uVar4 - 1) {
      if (*(int *)(iVar2 + 0x748) == param_2) {
        *(undefined *)(iVar1 + iVar3 * 8 + 0x74e) = 3;
        return;
      }
      iVar2 = iVar2 + 8;
      iVar3 = iVar3 + 1;
    }
    *(int *)(iVar1 + (uint)*(byte *)(iVar1 + 0x798) * 8 + 0x748) = param_2;
    *(undefined *)(iVar1 + (uint)*(byte *)(iVar1 + 0x798) * 8 + 0x74c) = param_3;
    *(char *)(iVar1 + (uint)*(byte *)(iVar1 + 0x798) * 8 + 0x74d) = (char)param_4;
    *(undefined *)(iVar1 + (uint)*(byte *)(iVar1 + 0x798) * 8 + 0x74e) = 3;
    *(char *)(iVar1 + 0x798) = *(char *)(iVar1 + 0x798) + '\x01';
  }
  return;
}

