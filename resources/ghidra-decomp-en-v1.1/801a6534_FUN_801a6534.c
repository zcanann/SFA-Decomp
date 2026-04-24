// Function: FUN_801a6534
// Entry: 801a6534
// Size: 140 bytes

void FUN_801a6534(int param_1)

{
  int *piVar1;
  int iVar2;
  int local_18 [4];
  
  iVar2 = *(int *)(param_1 + 0xb8);
  piVar1 = FUN_80037048(0x2f,local_18);
  if (0 < local_18[0]) {
    do {
      if (*piVar1 == param_1) {
        FUN_8003709c(param_1,0x2f);
        break;
      }
      piVar1 = piVar1 + 1;
      local_18[0] = local_18[0] + -1;
    } while (local_18[0] != 0);
  }
  if (*(char *)(iVar2 + 0x114) == '\x01') {
    DAT_803de7a0 = DAT_803de7a0 + -1;
  }
  return;
}

