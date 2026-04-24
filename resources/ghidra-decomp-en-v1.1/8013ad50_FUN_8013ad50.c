// Function: FUN_8013ad50
// Entry: 8013ad50
// Size: 388 bytes

void FUN_8013ad50(int param_1,int param_2,byte param_3)

{
  int iVar1;
  uint uVar2;
  
  iVar1 = 0;
  if (((*(int *)(param_1 + 0x528) == param_2) &&
      (*(short *)(param_1 + 0x530) == *(short *)(param_1 + 0x532))) &&
     (*(byte *)(param_1 + 0x536) == param_3)) {
    iVar1 = *(int *)(param_1 + 0x52c);
    if (iVar1 == 0) {
      iVar1 = 0;
    }
    else if ((((int)*(short *)(iVar1 + 0x30) != 0xffffffff) &&
             (uVar2 = FUN_80020078((int)*(short *)(iVar1 + 0x30)), uVar2 == 0)) ||
            (((int)*(short *)(iVar1 + 0x32) != 0xffffffff &&
             (uVar2 = FUN_80020078((int)*(short *)(iVar1 + 0x32)), uVar2 != 0)))) {
      iVar1 = 0;
    }
  }
  if (iVar1 == 0) {
    uVar2 = (uint)param_3;
    iVar1 = FUN_8013a874(param_1,param_2,(uint)*(ushort *)(param_1 + 0x532),uVar2);
    if (iVar1 == 0) {
      iVar1 = FUN_8013aa44(param_1,param_2,(uint)*(ushort *)(param_1 + 0x532));
    }
    if (iVar1 == 0) {
      if (*(ushort *)(param_1 + 0x534) != 0) {
        iVar1 = FUN_8013a874(param_1,param_2,(uint)*(ushort *)(param_1 + 0x534),uVar2);
        if (iVar1 == 0) {
          iVar1 = FUN_8013aa44(param_1,param_2,(uint)*(ushort *)(param_1 + 0x534));
        }
        if (iVar1 != 0) {
          *(undefined2 *)(param_1 + 0x532) = *(undefined2 *)(param_1 + 0x534);
        }
      }
      if (iVar1 == 0) {
        iVar1 = FUN_8013a874(param_1,param_2,0,uVar2);
        *(undefined2 *)(param_1 + 0x532) = 0;
      }
    }
  }
  *(int *)(param_1 + 0x528) = param_2;
  *(int *)(param_1 + 0x52c) = iVar1;
  *(undefined2 *)(param_1 + 0x530) = *(undefined2 *)(param_1 + 0x532);
  *(byte *)(param_1 + 0x536) = param_3;
  return;
}

