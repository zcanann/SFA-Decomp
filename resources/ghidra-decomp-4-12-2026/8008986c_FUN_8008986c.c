// Function: FUN_8008986c
// Entry: 8008986c
// Size: 304 bytes

void FUN_8008986c(uint param_1,byte param_2,byte param_3,byte param_4,uint param_5,uint param_6)

{
  uint uVar1;
  uint uVar2;
  int iVar3;
  int iVar4;
  int iVar5;
  
  if (DAT_803dddac != 0) {
    iVar4 = 0;
    iVar3 = 0;
    uVar1 = param_5 & 0xff;
    uVar2 = param_6 & 0xff;
    iVar5 = 2;
    do {
      if ((param_1 & 1 << iVar4) != 0) {
        *(byte *)(DAT_803dddac + iVar3 + 0x7c) = param_2;
        *(byte *)(DAT_803dddac + iVar3 + 0x7d) = param_3;
        *(byte *)(DAT_803dddac + iVar3 + 0x7e) = param_4;
        *(char *)(DAT_803dddac + iVar3 + 0x84) = (char)(param_2 * uVar1 >> 8);
        *(char *)(DAT_803dddac + iVar3 + 0x85) = (char)(param_3 * uVar1 >> 8);
        *(char *)(DAT_803dddac + iVar3 + 0x86) = (char)(param_4 * uVar1 >> 8);
        *(char *)(DAT_803dddac + iVar3 + 0x8c) = (char)(param_2 * uVar2 >> 8);
        *(char *)(DAT_803dddac + iVar3 + 0x8d) = (char)(param_3 * uVar2 >> 8);
        *(char *)(DAT_803dddac + iVar3 + 0x8e) = (char)(param_4 * uVar2 >> 8);
      }
      iVar3 = iVar3 + 0xa4;
      iVar4 = iVar4 + 1;
      iVar5 = iVar5 + -1;
    } while (iVar5 != 0);
  }
  return;
}

