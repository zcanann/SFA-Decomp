// Function: FUN_80278704
// Entry: 80278704
// Size: 268 bytes

void FUN_80278704(int param_1,int param_2)

{
  bool bVar1;
  
  if (param_2 == 0) {
    if ((*(int *)(param_1 + 0x34) != 0) && ((*(uint *)(param_1 + 0x114) & 0x400) != 0)) {
      if ((*(char *)(param_1 + 0x68) == '\0') || (*(int *)(param_1 + 0x50) == 0)) {
        bVar1 = false;
      }
      else {
        *(undefined4 *)(param_1 + 0x38) = *(undefined4 *)(param_1 + 0x5c);
        *(undefined4 *)(param_1 + 0x34) = *(undefined4 *)(param_1 + 0x50);
        *(undefined4 *)(param_1 + 0x50) = 0;
        FUN_80278990(param_1);
        bVar1 = true;
      }
      if ((!bVar1) && ((*(uint *)(param_1 + 0x118) & 4) != 0)) {
        FUN_80278990(param_1);
      }
    }
    *(undefined4 *)(param_1 + 0x118) = *(undefined4 *)(param_1 + 0x118);
    *(uint *)(param_1 + 0x114) = *(uint *)(param_1 + 0x114) & 0xfffffaff;
  }
  else {
    *(uint *)(param_1 + 0x114) = *(uint *)(param_1 + 0x114) | 0x100;
  }
  return;
}

