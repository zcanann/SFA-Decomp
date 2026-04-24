// Function: FUN_8001fe74
// Entry: 8001fe74
// Size: 28 bytes

void FUN_8001fe74(undefined4 param_1)

{
  uint uVar1;
  
  uVar1 = (uint)DAT_803dca48;
  DAT_803dca48 = DAT_803dca48 + 1;
  *(undefined4 *)(&DAT_803dcae8 + uVar1 * 4) = param_1;
  return;
}

