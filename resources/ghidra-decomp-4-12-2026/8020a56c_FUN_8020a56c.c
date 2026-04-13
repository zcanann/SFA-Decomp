// Function: FUN_8020a56c
// Entry: 8020a56c
// Size: 172 bytes

undefined4 FUN_8020a56c(int param_1)

{
  bool bVar1;
  int iVar2;
  int local_18 [4];
  
  local_18[0] = 0;
  if (((param_1 != 0) &&
      (iVar2 = FUN_80036974(param_1,local_18,(int *)0x0,(uint *)0x0), local_18[0] != 0)) &&
     (iVar2 != 0)) {
    iVar2 = 1;
    do {
      (**(code **)(*DAT_803dd708 + 8))(param_1,0x39e,0,1,0xffffffff,0);
      bVar1 = iVar2 < 0x14;
      iVar2 = iVar2 + 1;
    } while (bVar1);
  }
  return 0;
}

