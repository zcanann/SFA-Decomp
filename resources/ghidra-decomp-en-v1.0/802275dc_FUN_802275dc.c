// Function: FUN_802275dc
// Entry: 802275dc
// Size: 208 bytes

void FUN_802275dc(undefined2 *param_1,int param_2)

{
  int iVar1;
  int iVar2;
  
  iVar2 = *(int *)(param_1 + 0x5c);
  (**(code **)(*DAT_803dcaac + 0x40))((int)*(char *)(param_1 + 0x56));
  *param_1 = (short)((int)*(char *)(param_2 + 0x18) << 8);
  *(undefined *)((int)param_1 + 0xad) = *(undefined *)(param_2 + 0x19);
  if (*(char *)(*(int *)(param_1 + 0x28) + 0x55) <= *(char *)((int)param_1 + 0xad)) {
    *(undefined *)((int)param_1 + 0xad) = 0;
  }
  iVar1 = FUN_8001ffb4((int)*(short *)(param_2 + 0x20));
  if (iVar1 != 0) {
    iVar1 = FUN_8001ffb4((int)*(short *)(param_2 + 0x1e));
    if (iVar1 == 0) {
      *(undefined *)(iVar2 + 4) = 1;
    }
    else {
      *(undefined *)(iVar2 + 4) = 3;
    }
  }
  return;
}

