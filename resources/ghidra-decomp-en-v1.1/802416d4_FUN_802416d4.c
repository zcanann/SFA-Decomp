// Function: FUN_802416d4
// Entry: 802416d4
// Size: 104 bytes

void FUN_802416d4(undefined4 *param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4,
                 undefined4 param_5)

{
  longlong lVar1;
  longlong lVar2;
  
  FUN_80243e74();
  param_1[7] = 0;
  param_1[6] = 0;
  lVar2 = FUN_802473d4();
  lVar1 = lVar2 + CONCAT44(param_3,param_4);
  FUN_80241484(param_1,(int)lVar2,(uint)((ulonglong)lVar1 >> 0x20),(uint)lVar1,param_5);
  FUN_80243e9c();
  return;
}

