// Function: FUN_801b9dc4
// Entry: 801b9dc4
// Size: 124 bytes

void FUN_801b9dc4(int param_1)

{
  char *pcVar1;
  int iVar2;
  
  pcVar1 = *(char **)(param_1 + 0xb8);
  if ((pcVar1[2] & 1U) == 0) {
    iVar2 = *(int *)(param_1 + 0x4c);
    if (('\0' < *pcVar1) && (*pcVar1 = *pcVar1 + -1, *pcVar1 == '\0')) {
      pcVar1[2] = pcVar1[2] | 1;
      FUN_800201ac((int)*(short *)(iVar2 + 0x1e),1);
    }
  }
  return;
}

