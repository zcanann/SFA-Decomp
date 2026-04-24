// Function: FUN_80239114
// Entry: 80239114
// Size: 160 bytes

void FUN_80239114(int param_1)

{
  int iVar1;
  int iVar2;
  
  iVar2 = *(int *)(param_1 + 0x4c);
  iVar1 = FUN_8001ffb4((int)*(short *)(iVar2 + 0x1a));
  if (iVar1 == 0) {
    iVar1 = FUN_80038024(param_1);
    if (iVar1 == 0) {
      FUN_80041018(param_1);
    }
    else {
      FUN_800200e8((int)*(short *)(iVar2 + 0x1a),1);
      (**(code **)(*DAT_803dca54 + 0x48))(0,param_1,0xffffffff);
    }
  }
  else {
    *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) | 8;
  }
  return;
}

