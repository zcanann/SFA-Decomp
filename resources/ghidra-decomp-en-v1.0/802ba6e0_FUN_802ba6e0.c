// Function: FUN_802ba6e0
// Entry: 802ba6e0
// Size: 268 bytes

undefined4 FUN_802ba6e0(int param_1,uint *param_2)

{
  float fVar1;
  int iVar2;
  undefined4 uVar3;
  
  fVar1 = FLOAT_803e8234;
  param_2[0xa5] = (uint)FLOAT_803e8234;
  param_2[0xa1] = (uint)fVar1;
  param_2[0xa0] = (uint)fVar1;
  *(float *)(param_1 + 0x24) = fVar1;
  *(float *)(param_1 + 0x28) = fVar1;
  *(float *)(param_1 + 0x2c) = fVar1;
  *param_2 = *param_2 | 0x200000;
  if (*(char *)((int)param_2 + 0x27a) != '\0') {
    iVar2 = FUN_800221a0(0,1);
    param_2[0xa8] = *(uint *)(&DAT_803dc740 + iVar2 * 4);
    FUN_80030334((double)FLOAT_803e8234,param_1,(int)*(short *)(&DAT_803dc73c + iVar2 * 2),0);
  }
  if (*(char *)((int)param_2 + 0x346) == '\0') {
    if ((*(byte *)(param_1 + 0xaf) & 1) != 0) {
      iVar2 = FUN_800221a0(0,2);
      (**(code **)(*DAT_803dca54 + 0x48))(iVar2 + 6,param_1,0xffffffff);
      FUN_80014b3c(0,0x100);
    }
    uVar3 = 0;
  }
  else {
    uVar3 = 0xfffffffe;
  }
  return uVar3;
}

