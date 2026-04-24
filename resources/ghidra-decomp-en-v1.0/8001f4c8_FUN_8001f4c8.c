// Function: FUN_8001f4c8
// Entry: 8001f4c8
// Size: 132 bytes

int FUN_8001f4c8(undefined4 param_1,char param_2)

{
  int iVar1;
  uint uVar2;
  
  if (param_2 == '\0') {
    iVar1 = FUN_8001de4c();
    if (iVar1 == 0) {
      iVar1 = 0;
    }
  }
  else if (DAT_803dca30 < 0x32) {
    iVar1 = FUN_8001de4c();
    if (iVar1 == 0) {
      iVar1 = 0;
    }
    else {
      uVar2 = (uint)DAT_803dca30;
      DAT_803dca30 = DAT_803dca30 + 1;
      (&DAT_8033bec0)[uVar2] = iVar1;
    }
  }
  else {
    iVar1 = 0;
  }
  return iVar1;
}

