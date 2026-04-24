// Function: FUN_80227c84
// Entry: 80227c84
// Size: 208 bytes

void FUN_80227c84(undefined2 *param_1,int param_2)

{
  uint uVar1;
  int iVar2;
  
  iVar2 = *(int *)(param_1 + 0x5c);
  (**(code **)(*DAT_803dd72c + 0x40))((int)*(char *)(param_1 + 0x56));
  *param_1 = (short)((int)*(char *)(param_2 + 0x18) << 8);
  *(undefined *)((int)param_1 + 0xad) = *(undefined *)(param_2 + 0x19);
  if (*(char *)(*(int *)(param_1 + 0x28) + 0x55) <= *(char *)((int)param_1 + 0xad)) {
    *(undefined *)((int)param_1 + 0xad) = 0;
  }
  uVar1 = FUN_80020078((int)*(short *)(param_2 + 0x20));
  if (uVar1 != 0) {
    uVar1 = FUN_80020078((int)*(short *)(param_2 + 0x1e));
    if (uVar1 == 0) {
      *(undefined *)(iVar2 + 4) = 1;
    }
    else {
      *(undefined *)(iVar2 + 4) = 3;
    }
  }
  return;
}

