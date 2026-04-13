// Function: FUN_80038378
// Entry: 80038378
// Size: 112 bytes

void FUN_80038378(undefined4 param_1,undefined4 param_2,int param_3,float *param_4)

{
  int iVar1;
  undefined8 uVar2;
  
  uVar2 = FUN_80286840();
  for (iVar1 = 0; iVar1 < param_3; iVar1 = iVar1 + 1) {
    FUN_80038524((int)((ulonglong)uVar2 >> 0x20),(int)uVar2 + iVar1,param_4,param_4 + 1,param_4 + 2,
                 0);
    param_4 = param_4 + 3;
  }
  FUN_8028688c();
  return;
}

