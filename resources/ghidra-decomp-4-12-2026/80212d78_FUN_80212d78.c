// Function: FUN_80212d78
// Entry: 80212d78
// Size: 212 bytes

undefined4 FUN_80212d78(undefined4 param_1,int param_2)

{
  int iVar1;
  
  if (*(char *)(param_2 + 0x27b) == '\0') {
    if (*(char *)(param_2 + 0x346) != '\0') {
      *(uint *)(DAT_803de9d4 + 0xc) = *(ushort *)(DAT_803de9d4 + 0xfa) >> 1 & 3;
      *(float *)(DAT_803de9d4 + 4) = FLOAT_803e7470;
      FUN_8000a538((int *)0x93,0);
      FUN_8000a538((int *)0x94,1);
      return 0xb;
    }
  }
  else {
    (**(code **)(*DAT_803dd70c + 0x14))(param_1,param_2,8);
    iVar1 = (**(code **)(*DAT_803dd6d0 + 0x10))();
    if (iVar1 == 0x42) {
      (**(code **)(*DAT_803dd6d0 + 0x24))(2,0,0);
    }
  }
  return 0;
}

