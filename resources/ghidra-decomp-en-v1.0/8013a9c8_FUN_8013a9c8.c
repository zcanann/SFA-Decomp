// Function: FUN_8013a9c8
// Entry: 8013a9c8
// Size: 388 bytes

void FUN_8013a9c8(int param_1,int param_2,char param_3)

{
  int iVar1;
  int iVar2;
  
  iVar1 = 0;
  if (((*(int *)(param_1 + 0x528) == param_2) &&
      (*(short *)(param_1 + 0x530) == *(short *)(param_1 + 0x532))) &&
     (*(char *)(param_1 + 0x536) == param_3)) {
    iVar1 = *(int *)(param_1 + 0x52c);
    if (iVar1 == 0) {
      iVar1 = 0;
    }
    else if (((*(short *)(iVar1 + 0x30) != -1) && (iVar2 = FUN_8001ffb4(), iVar2 == 0)) ||
            ((*(short *)(iVar1 + 0x32) != -1 && (iVar2 = FUN_8001ffb4(), iVar2 != 0)))) {
      iVar1 = 0;
    }
  }
  if (iVar1 == 0) {
    iVar1 = FUN_8013a4ec(param_1,param_2,*(undefined2 *)(param_1 + 0x532),param_3);
    if (iVar1 == 0) {
      iVar1 = FUN_8013a6bc(param_1,param_2,*(undefined2 *)(param_1 + 0x532));
    }
    if (iVar1 == 0) {
      if (*(short *)(param_1 + 0x534) != 0) {
        iVar1 = FUN_8013a4ec(param_1,param_2,*(short *)(param_1 + 0x534),param_3);
        if (iVar1 == 0) {
          iVar1 = FUN_8013a6bc(param_1,param_2,*(undefined2 *)(param_1 + 0x534));
        }
        if (iVar1 != 0) {
          *(undefined2 *)(param_1 + 0x532) = *(undefined2 *)(param_1 + 0x534);
        }
      }
      if (iVar1 == 0) {
        iVar1 = FUN_8013a4ec(param_1,param_2,0,param_3);
        *(undefined2 *)(param_1 + 0x532) = 0;
      }
    }
  }
  *(int *)(param_1 + 0x528) = param_2;
  *(int *)(param_1 + 0x52c) = iVar1;
  *(undefined2 *)(param_1 + 0x530) = *(undefined2 *)(param_1 + 0x532);
  *(char *)(param_1 + 0x536) = param_3;
  return;
}

