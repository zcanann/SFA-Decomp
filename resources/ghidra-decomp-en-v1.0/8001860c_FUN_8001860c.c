// Function: FUN_8001860c
// Entry: 8001860c
// Size: 224 bytes

int FUN_8001860c(int param_1)

{
  uint uVar1;
  uint *puVar2;
  int iVar3;
  int iVar4;
  int iVar5;
  int local_18 [3];
  
  iVar4 = 0;
  iVar3 = 0;
  if (param_1 == 0) {
    iVar4 = 0;
  }
  else {
    while (uVar1 = FUN_80015cb8(param_1 + iVar3,local_18), uVar1 != 0) {
      iVar3 = iVar3 + local_18[0];
      if ((uVar1 < 0xe000) || (0xf8ff < uVar1)) {
        iVar4 = iVar4 + 1;
      }
      else {
        puVar2 = &DAT_802c86f0;
        iVar5 = 0x17;
        do {
          if (*puVar2 == uVar1) {
            uVar1 = puVar2[1];
            goto LAB_800186ac;
          }
          if (puVar2[2] == uVar1) {
            uVar1 = puVar2[3];
            goto LAB_800186ac;
          }
          puVar2 = puVar2 + 4;
          iVar5 = iVar5 + -1;
        } while (iVar5 != 0);
        uVar1 = 0;
LAB_800186ac:
        iVar3 = iVar3 + uVar1 * 2;
      }
    }
  }
  return iVar4;
}

