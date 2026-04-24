// Function: FUN_80143388
// Entry: 80143388
// Size: 296 bytes

undefined4 FUN_80143388(int param_1,int param_2)

{
  int iVar1;
  int iVar2;
  int iVar3;
  
  iVar1 = FUN_8014460c();
  if (iVar1 == 0) {
    for (iVar1 = 0; iVar1 < *(char *)(param_2 + 0x827); iVar1 = iVar1 + 1) {
      if ((((*(char *)(param_2 + iVar1 + 0x81f) == '\0') &&
           (iVar3 = *(int *)(param_1 + 0xb8), (*(byte *)(iVar3 + 0x58) >> 6 & 1) == 0)) &&
          ((0x2f < *(short *)(param_1 + 0xa0) || (*(short *)(param_1 + 0xa0) < 0x29)))) &&
         (iVar2 = FUN_8000b578(param_1,0x10), iVar2 == 0)) {
        FUN_800393f8(param_1,iVar3 + 0x3a8,0x357,0,0xffffffff,0);
      }
    }
    iVar1 = FUN_8014460c(param_1,param_2);
    if (((iVar1 == 0) && ((*(uint *)(param_2 + 0x54) & 0x8000000) != 0)) &&
       (*(int *)(param_2 + 0x20) == (int)*(short *)(param_1 + 0xa0))) {
      *(undefined *)(param_2 + 10) = 0;
    }
  }
  return 1;
}

