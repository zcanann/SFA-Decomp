// Function: FUN_80042e74
// Entry: 80042e74
// Size: 260 bytes

void FUN_80042e74(int param_1)

{
  int iVar1;
  
  if (*(short *)(&DAT_802cbdfc + param_1 * 2) != -1) {
    iVar1 = (**(code **)(*DAT_803dcaac + 0x90))();
    *(char *)(iVar1 + 0xe) = (char)param_1;
  }
  FUN_800443cc(param_1,0x20);
  FUN_800443cc(param_1,0x21);
  FUN_800443cc(param_1,0x23);
  FUN_800443cc(param_1,0x24);
  FUN_800443cc(param_1,0x30);
  FUN_800443cc(param_1,0x2f);
  FUN_800443cc(param_1,0x2b);
  FUN_800443cc(param_1,0x2a);
  FUN_800443cc(param_1,0x26);
  FUN_800443cc(param_1,0x25);
  FUN_800443cc(param_1,0x1a);
  FUN_800443cc(param_1,0x1b);
  FUN_800443cc(param_1,0xe);
  FUN_800443cc(param_1,0xd);
  return;
}

