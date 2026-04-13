// Function: FUN_802217c8
// Entry: 802217c8
// Size: 164 bytes

bool FUN_802217c8(int param_1)

{
  uint uVar1;
  int iVar2;
  
  iVar2 = *(int *)(param_1 + 0x4c);
  uVar1 = FUN_80020078((int)*(short *)(iVar2 + 0x1e));
  if (uVar1 != 0) {
    FUN_800201ac(0x7a9,(int)*(char *)(iVar2 + 0x19));
    (**(code **)(*DAT_803dd72c + 0x50))((int)*(char *)(param_1 + 0xac),0xc,1);
    (**(code **)(*DAT_803dd6d4 + 0x48))(2,param_1,0xffffffff);
  }
  return uVar1 != 0;
}

