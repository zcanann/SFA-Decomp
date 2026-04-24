// Function: FUN_80035828
// Entry: 80035828
// Size: 172 bytes

void FUN_80035828(undefined4 param_1,undefined4 param_2,int param_3,int param_4,undefined4 param_5)

{
  undefined8 uVar1;
  
  uVar1 = FUN_802860dc();
  if ((int)uVar1 != 0) {
    *(undefined2 *)(param_3 + 6) = 300;
    param_4 = FUN_80022e3c(param_4);
    *(int *)(param_3 + 8) = param_4;
    param_4 = param_4 + *(short *)(param_3 + 6);
    *(undefined *)(param_3 + 0xae) = 1;
    if ((*(byte *)(param_3 + 0x62) & 0x30) != 0) {
      *(undefined *)(param_3 + 0xaf) = 2;
    }
    FUN_80035774(param_5,(int)uVar1,(int)((ulonglong)uVar1 >> 0x20),param_3,0,1);
  }
  FUN_80286128(param_4);
  return;
}

