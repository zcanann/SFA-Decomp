// Function: FUN_80221178
// Entry: 80221178
// Size: 164 bytes

bool FUN_80221178(int param_1)

{
  int iVar1;
  int iVar2;
  
  iVar2 = *(int *)(param_1 + 0x4c);
  iVar1 = FUN_8001ffb4((int)*(short *)(iVar2 + 0x1e));
  if (iVar1 != 0) {
    FUN_800200e8(0x7a9,(int)*(char *)(iVar2 + 0x19));
    (**(code **)(*DAT_803dcaac + 0x50))((int)*(char *)(param_1 + 0xac),0xc,1);
    (**(code **)(*DAT_803dca54 + 0x48))(2,param_1,0xffffffff);
  }
  return iVar1 != 0;
}

