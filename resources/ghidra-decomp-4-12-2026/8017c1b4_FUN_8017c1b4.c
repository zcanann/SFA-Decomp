// Function: FUN_8017c1b4
// Entry: 8017c1b4
// Size: 148 bytes

void FUN_8017c1b4(undefined2 *param_1)

{
  int iVar1;
  uint uVar2;
  int iVar3;
  
  iVar3 = *(int *)(param_1 + 0x26);
  iVar1 = FUN_800395a4((int)param_1,0);
  if (iVar1 != 0) {
    *(undefined2 *)(iVar1 + 8) = 0x800;
  }
  *param_1 = (short)((int)*(char *)(iVar3 + 0x18) << 8);
  param_1[0x58] = param_1[0x58] | 0x6000;
  FUN_80035ff8((int)param_1);
  uVar2 = FUN_80020078((int)*(short *)(iVar3 + 0x1e));
  if (uVar2 != 0) {
    FUN_80036018((int)param_1);
  }
  return;
}

