// Function: FUN_801e1f18
// Entry: 801e1f18
// Size: 196 bytes

void FUN_801e1f18(int param_1,int param_2)

{
  int iVar1;
  
  iVar1 = *(int *)(param_1 + 0xb8);
  if (DAT_803ddc18 != 0) {
    FUN_80054308();
    DAT_803ddc18 = 0;
  }
  if (DAT_803ddc1c != 0) {
    FUN_80054308();
    DAT_803ddc1c = 0;
  }
  FUN_80036fa4(param_1,3);
  if ((*(char *)(iVar1 + 0x80) != '\0') && (param_2 == 0)) {
    *(undefined *)(iVar1 + 0x80) = 0;
  }
  DAT_803ddc20 = 0;
  FUN_8000a518(*(undefined4 *)(iVar1 + 0x9c),0);
  FUN_8000a518(*(undefined4 *)(iVar1 + 0x98),0);
  FUN_800200e8(0xac8,1);
  return;
}

