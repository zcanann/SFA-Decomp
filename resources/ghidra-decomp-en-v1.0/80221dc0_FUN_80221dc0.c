// Function: FUN_80221dc0
// Entry: 80221dc0
// Size: 212 bytes

void FUN_80221dc0(undefined8 param_1,undefined4 *param_2,undefined4 param_3,undefined4 param_4)

{
  int iVar1;
  undefined auStack72 [8];
  undefined auStack64 [8];
  undefined auStack56 [8];
  undefined auStack48 [12];
  undefined4 local_24;
  undefined4 local_20;
  undefined4 local_1c;
  
  FUN_80247794(param_4,param_4);
  FUN_80247778(param_1,param_4,auStack48);
  FUN_80247730(auStack48,param_3,&local_24);
  FUN_80012d00(param_3,auStack56);
  FUN_80012d00(&local_24,auStack64);
  iVar1 = FUN_800128dc(auStack56,auStack64,auStack72,0,0);
  if (iVar1 == 0) {
    FUN_80012e0c(&local_24,auStack72);
  }
  *param_2 = local_24;
  param_2[1] = local_20;
  param_2[2] = local_1c;
  return;
}

