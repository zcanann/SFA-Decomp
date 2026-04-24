// Function: FUN_800895e0
// Entry: 800895e0
// Size: 304 bytes

void FUN_800895e0(uint param_1,byte param_2,byte param_3,byte param_4,uint param_5,uint param_6)

{
  int iVar1;
  int iVar2;
  int iVar3;
  
  if (DAT_803dd12c != 0) {
    iVar2 = 0;
    iVar1 = 0;
    param_5 = param_5 & 0xff;
    param_6 = param_6 & 0xff;
    iVar3 = 2;
    do {
      if ((param_1 & 1 << iVar2) != 0) {
        *(byte *)(DAT_803dd12c + iVar1 + 0x7c) = param_2;
        *(byte *)(DAT_803dd12c + iVar1 + 0x7d) = param_3;
        *(byte *)(DAT_803dd12c + iVar1 + 0x7e) = param_4;
        *(char *)(DAT_803dd12c + iVar1 + 0x84) = (char)(param_2 * param_5 >> 8);
        *(char *)(DAT_803dd12c + iVar1 + 0x85) = (char)(param_3 * param_5 >> 8);
        *(char *)(DAT_803dd12c + iVar1 + 0x86) = (char)(param_4 * param_5 >> 8);
        *(char *)(DAT_803dd12c + iVar1 + 0x8c) = (char)(param_2 * param_6 >> 8);
        *(char *)(DAT_803dd12c + iVar1 + 0x8d) = (char)(param_3 * param_6 >> 8);
        *(char *)(DAT_803dd12c + iVar1 + 0x8e) = (char)(param_4 * param_6 >> 8);
      }
      iVar1 = iVar1 + 0xa4;
      iVar2 = iVar2 + 1;
      iVar3 = iVar3 + -1;
    } while (iVar3 != 0);
  }
  return;
}

