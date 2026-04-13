// Function: FUN_8024fd4c
// Entry: 8024fd4c
// Size: 84 bytes

undefined4 FUN_8024fd4c(int param_1)

{
  undefined4 uVar1;
  
  uVar1 = DAT_803dec4c;
  DAT_803dec4c = param_1;
  if (param_1 == 0) {
    FUN_80252904(-0x7fdb0314);
  }
  else {
    FUN_80252838(-0x7fdb0314);
  }
  return uVar1;
}

