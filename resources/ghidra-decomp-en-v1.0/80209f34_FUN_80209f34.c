// Function: FUN_80209f34
// Entry: 80209f34
// Size: 172 bytes

undefined4 FUN_80209f34(int param_1)

{
  bool bVar1;
  int iVar2;
  int local_18 [4];
  
  local_18[0] = 0;
  if (((param_1 != 0) && (iVar2 = FUN_8003687c(param_1,local_18,0,0), local_18[0] != 0)) &&
     (iVar2 != 0)) {
    iVar2 = 1;
    do {
      (**(code **)(*DAT_803dca88 + 8))(param_1,0x39e,0,1,0xffffffff,0);
      bVar1 = iVar2 < 0x14;
      iVar2 = iVar2 + 1;
    } while (bVar1);
  }
  return 0;
}

