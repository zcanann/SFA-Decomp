// Function: FUN_8028314c
// Entry: 8028314c
// Size: 196 bytes

undefined4 FUN_8028314c(undefined4 param_1,undefined param_2,undefined param_3,uint param_4)

{
  int iVar1;
  undefined4 uVar2;
  
  FUN_80284a8c();
  DAT_803de37f = 0;
  DAT_803de37e = 0;
  DAT_803de348 = 0;
  iVar1 = FUN_8028478c(&LAB_80282fe0,param_4,param_1);
  if (((iVar1 == 0) || (iVar1 = FUN_8027ba04(param_2,param_3,(param_4 & 1) != 0), iVar1 == 0)) ||
     (iVar1 = FUN_802848d8(param_4), iVar1 == 0)) {
    uVar2 = 0xffffffff;
  }
  else {
    FUN_80284abc();
    FUN_80284858();
    uVar2 = 0;
  }
  return uVar2;
}

