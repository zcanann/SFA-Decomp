// Function: FUN_801e6948
// Entry: 801e6948
// Size: 104 bytes

undefined4 FUN_801e6948(undefined4 param_1,int param_2)

{
  uint uVar1;
  undefined4 uVar2;
  
  FUN_8002bac4();
  uVar2 = 0;
  if (((int)*(short *)(&DAT_80328c16 + param_2 * 0xc) == 0xffffffff) ||
     (uVar1 = FUN_80020078((int)*(short *)(&DAT_80328c16 + param_2 * 0xc)), uVar1 != 0)) {
    uVar2 = 1;
  }
  return uVar2;
}

