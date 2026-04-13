// Function: FUN_80130240
// Entry: 80130240
// Size: 320 bytes

int FUN_80130240(int *param_1)

{
  int iVar1;
  uint uVar2;
  uint uVar3;
  char local_18;
  undefined auStack_17 [19];
  
  iVar1 = FUN_80020800();
  if (iVar1 != 0) {
    return -1;
  }
  FLOAT_803de56c = FLOAT_803de56c + FLOAT_803dc074;
  if (FLOAT_803e2e68 < FLOAT_803de56c) {
    FLOAT_803de56c = FLOAT_803de56c - FLOAT_803e2e68;
  }
  FUN_80014ba4(0,auStack_17,&local_18);
  if (local_18 < '\0') {
    *param_1 = *param_1 + 1;
  }
  else if ('\0' < local_18) {
    *param_1 = *param_1 + -1;
  }
  if (*param_1 < 0) {
    *param_1 = DAT_803de570 + -1;
  }
  if ((int)DAT_803de570 <= *param_1) {
    *param_1 = 0;
  }
  if (DAT_803de568 != '\0') {
    uVar2 = FUN_80014e9c(0);
    if (((uVar2 & 0x1100) != 0) && (uVar3 = FUN_80020078(0x44f), uVar3 == 0)) {
      return (int)DAT_803de575;
    }
    if ((uVar2 & 0x200) != 0) {
      return (int)DAT_803de574;
    }
  }
  DAT_803de568 = 1;
  return -1;
}

