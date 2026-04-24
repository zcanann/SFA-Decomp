// Function: FUN_801a5f80
// Entry: 801a5f80
// Size: 140 bytes

void FUN_801a5f80(int param_1)

{
  int *piVar1;
  int iVar2;
  int local_18 [4];
  
  iVar2 = *(int *)(param_1 + 0xb8);
  piVar1 = (int *)FUN_80036f50(0x2f,local_18);
  if (0 < local_18[0]) {
    do {
      if (*piVar1 == param_1) {
        FUN_80036fa4(param_1,0x2f);
        break;
      }
      piVar1 = piVar1 + 1;
      local_18[0] = local_18[0] + -1;
    } while (local_18[0] != 0);
  }
  if (*(char *)(iVar2 + 0x114) == '\x01') {
    DAT_803ddb20 = DAT_803ddb20 + -1;
  }
  return;
}

