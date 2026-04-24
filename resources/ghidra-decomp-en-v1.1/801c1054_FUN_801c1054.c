// Function: FUN_801c1054
// Entry: 801c1054
// Size: 148 bytes

void FUN_801c1054(int param_1)

{
  uint uVar1;
  char *pcVar2;
  
  uVar1 = (uint)*(short *)(*(int *)(param_1 + 0x4c) + 0x1c);
  if (uVar1 != 0xffffffff) {
    pcVar2 = *(char **)(param_1 + 0xb8);
    uVar1 = FUN_80020078(uVar1);
    if (uVar1 == 0) {
      if (*pcVar2 == '\0') {
        *pcVar2 = '\x01';
        FUN_800372f8(param_1,0x14);
      }
    }
    else if (*pcVar2 != '\0') {
      *pcVar2 = '\0';
      FUN_8003709c(param_1,0x14);
    }
  }
  return;
}

