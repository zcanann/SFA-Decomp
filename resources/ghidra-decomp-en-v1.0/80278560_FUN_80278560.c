// Function: FUN_80278560
// Entry: 80278560
// Size: 176 bytes

void FUN_80278560(int param_1)

{
  bool bVar1;
  
  if (*(int *)(param_1 + 0x4c) == 1) {
    if ((*(char *)(param_1 + 0x68) == '\0') || (*(int *)(param_1 + 0x54) == 0)) {
      bVar1 = false;
    }
    else {
      *(undefined4 *)(param_1 + 0x38) = *(undefined4 *)(param_1 + 0x60);
      *(undefined4 *)(param_1 + 0x34) = *(undefined4 *)(param_1 + 0x54);
      *(undefined4 *)(param_1 + 0x54) = 0;
      FUN_80278990(param_1);
      bVar1 = true;
    }
    if ((!bVar1) && ((*(uint *)(param_1 + 0x118) & 0x40000) != 0)) {
      FUN_80278990(param_1);
    }
  }
  return;
}

