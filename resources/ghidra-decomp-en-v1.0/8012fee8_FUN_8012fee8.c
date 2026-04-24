// Function: FUN_8012fee8
// Entry: 8012fee8
// Size: 320 bytes

int FUN_8012fee8(int *param_1)

{
  int iVar1;
  uint uVar2;
  char local_18;
  undefined auStack23 [19];
  
  iVar1 = FUN_8002073c();
  if (iVar1 != 0) {
    return -1;
  }
  FLOAT_803dd8ec = FLOAT_803dd8ec + FLOAT_803db414;
  if (FLOAT_803e21d8 < FLOAT_803dd8ec) {
    FLOAT_803dd8ec = FLOAT_803dd8ec - FLOAT_803e21d8;
  }
  FUN_80014b78(0,auStack23,&local_18);
  if (local_18 < '\0') {
    *param_1 = *param_1 + 1;
  }
  else if ('\0' < local_18) {
    *param_1 = *param_1 + -1;
  }
  if (*param_1 < 0) {
    *param_1 = DAT_803dd8f0 + -1;
  }
  if ((int)DAT_803dd8f0 <= *param_1) {
    *param_1 = 0;
  }
  if (DAT_803dd8e8 != '\0') {
    uVar2 = FUN_80014e70(0);
    if (((uVar2 & 0x1100) != 0) && (iVar1 = FUN_8001ffb4(0x44f), iVar1 == 0)) {
      return (int)DAT_803dd8f5;
    }
    if ((uVar2 & 0x200) != 0) {
      return (int)DAT_803dd8f4;
    }
  }
  DAT_803dd8e8 = 1;
  return -1;
}

