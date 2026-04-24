// Function: FUN_80022d20
// Entry: 80022d20
// Size: 28 bytes

undefined4 FUN_80022d20(undefined4 param_1)

{
  undefined4 uVar1;
  
  uVar1 = DAT_803db434;
  DAT_803db434 = param_1;
  DAT_803dcb14 = DAT_803dcb14 + 1;
  return uVar1;
}

