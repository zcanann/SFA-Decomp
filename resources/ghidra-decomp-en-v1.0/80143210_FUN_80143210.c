// Function: FUN_80143210
// Entry: 80143210
// Size: 188 bytes

undefined4 FUN_80143210(int param_1,int param_2)

{
  short sVar1;
  int iVar2;
  
  iVar2 = FUN_8014460c();
  if (iVar2 == 0) {
    sVar1 = *(short *)(param_1 + 0xa0);
    if (sVar1 == 0x24) {
      if (((*(uint *)(param_2 + 0x54) & 0x8000000) != 0) && (iVar2 = FUN_800221a0(0,3), iVar2 == 0))
      {
        *(undefined *)(param_2 + 10) = 0;
      }
    }
    else if (((sVar1 < 0x24) && (0x22 < sVar1)) && ((*(uint *)(param_2 + 0x54) & 0x8000000) != 0)) {
      FUN_8013a3f0((double)FLOAT_803e2478,param_1,0x24,0);
    }
  }
  return 1;
}

