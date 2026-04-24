// Function: FUN_80278610
// Entry: 80278610
// Size: 244 bytes

uint FUN_80278610(int param_1)

{
  bool bVar1;
  uint uVar2;
  
  uVar2 = *(uint *)(param_1 + 0x114);
  *(uint *)(param_1 + 0x118) = *(uint *)(param_1 + 0x118) | 8;
  if (*(int *)(param_1 + 0x34) != 0) {
    uVar2 = 0;
    if ((*(uint *)(param_1 + 0x114) & 0x100) == 0) {
      if ((*(char *)(param_1 + 0x68) == '\0') || (*(int *)(param_1 + 0x50) == 0)) {
        bVar1 = false;
      }
      else {
        *(undefined4 *)(param_1 + 0x38) = *(undefined4 *)(param_1 + 0x5c);
        *(undefined4 *)(param_1 + 0x34) = *(undefined4 *)(param_1 + 0x50);
        *(undefined4 *)(param_1 + 0x50) = 0;
        uVar2 = FUN_80278990(param_1);
        bVar1 = true;
      }
      if (!bVar1) {
        uVar2 = *(uint *)(param_1 + 0x118) & 4;
        if (uVar2 != 0) {
          uVar2 = FUN_80278990(param_1);
        }
      }
    }
    else {
      *(undefined4 *)(param_1 + 0x118) = *(undefined4 *)(param_1 + 0x118);
      *(uint *)(param_1 + 0x114) = *(uint *)(param_1 + 0x114) | 0x400;
    }
  }
  return uVar2;
}

