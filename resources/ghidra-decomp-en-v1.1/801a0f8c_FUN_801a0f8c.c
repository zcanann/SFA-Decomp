// Function: FUN_801a0f8c
// Entry: 801a0f8c
// Size: 232 bytes

void FUN_801a0f8c(int param_1)

{
  uint uVar1;
  int iVar2;
  char *pcVar3;
  
  pcVar3 = *(char **)(param_1 + 0xb8);
  iVar2 = *(int *)(param_1 + 0x4c);
  if (*pcVar3 == '\0') {
    uVar1 = FUN_80020078((int)*(short *)(iVar2 + 0x1e));
    uVar1 = countLeadingZeros(uVar1);
    *pcVar3 = (char)(uVar1 >> 5);
    if ((uVar1 >> 5 & 0xff) != 0) {
      FUN_800372f8(param_1,0x4e);
    }
    if (*(char *)(param_1 + 0x36) != '\0') {
      *(char *)(param_1 + 0x36) = *(char *)(param_1 + 0x36) + -1;
    }
  }
  else {
    FUN_80098da4(param_1,5,0,0,(undefined4 *)0x0);
    uVar1 = FUN_80020078((int)*(short *)(iVar2 + 0x1e));
    uVar1 = countLeadingZeros(uVar1);
    *pcVar3 = (char)(uVar1 >> 5);
    if ((uVar1 >> 5 & 0xff) == 0) {
      FUN_8003709c(param_1,0x4e);
    }
    if (*(char *)(param_1 + 0x36) != -1) {
      *(char *)(param_1 + 0x36) = *(char *)(param_1 + 0x36) + '\x01';
    }
  }
  return;
}

