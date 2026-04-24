// Function: FUN_80244758
// Entry: 80244758
// Size: 200 bytes

undefined4 FUN_80244758(int *param_1,undefined4 param_2,uint param_3)

{
  int iVar1;
  int iVar2;
  
  FUN_80243e74();
  while( true ) {
    iVar2 = param_1[5];
    if (param_1[7] < iVar2) {
      iVar1 = param_1[6] + param_1[7];
      *(undefined4 *)(param_1[4] + (iVar1 - (iVar1 / iVar2) * iVar2) * 4) = param_2;
      param_1[7] = param_1[7] + 1;
      FUN_802472b0(param_1 + 2);
      FUN_80243e9c();
      return 1;
    }
    if ((param_3 & 1) == 0) break;
    FUN_802471c4(param_1);
  }
  FUN_80243e9c();
  return 0;
}

