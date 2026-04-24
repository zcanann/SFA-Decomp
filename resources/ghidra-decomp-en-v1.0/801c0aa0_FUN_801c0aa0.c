// Function: FUN_801c0aa0
// Entry: 801c0aa0
// Size: 148 bytes

void FUN_801c0aa0(int param_1)

{
  int iVar1;
  char *pcVar2;
  
  if (*(short *)(*(int *)(param_1 + 0x4c) + 0x1c) != -1) {
    pcVar2 = *(char **)(param_1 + 0xb8);
    iVar1 = FUN_8001ffb4();
    if (iVar1 == 0) {
      if (*pcVar2 == '\0') {
        *pcVar2 = '\x01';
        FUN_80037200(param_1,0x14);
      }
    }
    else if (*pcVar2 != '\0') {
      *pcVar2 = '\0';
      FUN_80036fa4(param_1,0x14);
    }
  }
  return;
}

