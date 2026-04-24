// Function: FUN_8028f074
// Entry: 8028f074
// Size: 112 bytes

int FUN_8028f074(int param_1)

{
  uint uVar1;
  ushort uVar2;
  int iVar3;
  
  uVar2 = *(ushort *)(param_1 + 4) >> 6 & 7;
  if ((uVar2 == 1) || (uVar2 == 2)) {
    if (*(char *)(param_1 + 10) == '\0') {
      uVar1 = (uint)(*(byte *)(param_1 + 8) >> 5);
      if (uVar1 == 0) {
        return *(int *)(param_1 + 0x18);
      }
      iVar3 = *(int *)(param_1 + 0x34) + (*(int *)(param_1 + 0x24) - *(int *)(param_1 + 0x1c));
      if (uVar1 < 3) {
        return iVar3;
      }
      return iVar3 - (uVar1 - 2);
    }
  }
  DAT_803de408 = 0x28;
  return -1;
}

