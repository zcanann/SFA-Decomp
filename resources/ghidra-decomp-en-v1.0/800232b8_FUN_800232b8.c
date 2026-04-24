// Function: FUN_800232b8
// Entry: 800232b8
// Size: 84 bytes

int FUN_800232b8(uint param_1)

{
  uint uVar1;
  undefined4 *puVar2;
  int iVar3;
  
  iVar3 = 0;
  puVar2 = &DAT_803406a0;
  uVar1 = (uint)DAT_803dcb42;
  while( true ) {
    if (uVar1 == 0) {
      return -1;
    }
    if (((uint)puVar2[2] < param_1) && (param_1 < (uint)(puVar2[2] + puVar2[3]))) break;
    puVar2 = puVar2 + 5;
    iVar3 = iVar3 + 1;
    uVar1 = uVar1 - 1;
  }
  return iVar3;
}

