// Function: FUN_80022d3c
// Entry: 80022d3c
// Size: 28 bytes

undefined4 FUN_80022d3c(undefined4 param_1)

{
  undefined4 uVar1;
  
  uVar1 = DAT_803dcb08;
  DAT_803dcb08 = param_1;
  DAT_803dcb14 = DAT_803dcb14 + 1;
  return uVar1;
}

