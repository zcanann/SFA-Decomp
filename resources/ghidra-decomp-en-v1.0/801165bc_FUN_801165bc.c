// Function: FUN_801165bc
// Entry: 801165bc
// Size: 264 bytes

void FUN_801165bc(undefined4 param_1)

{
  char cVar2;
  int iVar1;
  
  cVar2 = FUN_80134bbc();
  if (cVar2 == '\0') {
    iVar1 = (**(code **)(*DAT_803dca50 + 0x10))();
    if (iVar1 == 0x57) {
      FUN_8001b444(FUN_80135a90);
      FUN_80135820((double)(FLOAT_803e1d10 +
                           (float)((double)CONCAT44(0x43300000,
                                                    (uint)DAT_803dd616 * 0x1a4 ^ 0x80000000) -
                                  DOUBLE_803e1d20) / FLOAT_803e1d14),(double)FLOAT_803e1d18);
      FUN_80134d40(0,0,0);
      (**(code **)(*DAT_803dca4c + 0x18))();
      (**(code **)(*DAT_803dcaa0 + 0x30))(0xff);
      (**(code **)(*DAT_803dcaa0 + 0x10))(param_1);
      FUN_8001b444(0);
      FUN_80134c28(DAT_803dd64f);
    }
  }
  else {
    FUN_801349c8();
  }
  return;
}

