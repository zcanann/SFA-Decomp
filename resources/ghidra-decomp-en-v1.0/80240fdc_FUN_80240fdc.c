// Function: FUN_80240fdc
// Entry: 80240fdc
// Size: 104 bytes

void FUN_80240fdc(int param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4,
                 undefined4 param_5)

{
  longlong lVar1;
  undefined4 uVar2;
  longlong lVar3;
  
  uVar2 = FUN_8024377c();
  *(undefined4 *)(param_1 + 0x1c) = 0;
  *(undefined4 *)(param_1 + 0x18) = 0;
  lVar3 = FUN_80246c70();
  lVar1 = lVar3 + CONCAT44(param_3,param_4);
  FUN_80240d8c(param_1,(int)lVar3,(int)((ulonglong)lVar1 >> 0x20),(int)lVar1,param_5);
  FUN_802437a4(uVar2);
  return;
}

