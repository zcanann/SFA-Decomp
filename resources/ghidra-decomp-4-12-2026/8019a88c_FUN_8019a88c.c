// Function: FUN_8019a88c
// Entry: 8019a88c
// Size: 156 bytes

void FUN_8019a88c(int param_1)

{
  byte *pbVar1;
  byte bVar2;
  
  pbVar1 = (byte *)(*(int *)(param_1 + 0x4c) + 0x18);
  for (bVar2 = 0; bVar2 < 8; bVar2 = bVar2 + 1) {
    if ((((*pbVar1 & 3) != 0) && (pbVar1[1] != 3)) && (pbVar1[1] == 4)) {
      FUN_8000b844(param_1,*(short *)(pbVar1 + 2));
    }
    pbVar1 = pbVar1 + 4;
  }
  return;
}

