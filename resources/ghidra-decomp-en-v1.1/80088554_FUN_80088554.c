// Function: FUN_80088554
// Entry: 80088554
// Size: 28 bytes

undefined FUN_80088554(int param_1)

{
  undefined uVar1;
  
  uVar1 = (&DAT_8039ab08)[param_1];
  (&DAT_8039ab08)[param_1] = 0;
  return uVar1;
}

