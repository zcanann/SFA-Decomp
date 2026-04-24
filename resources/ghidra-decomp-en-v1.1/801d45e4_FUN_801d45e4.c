// Function: FUN_801d45e4
// Entry: 801d45e4
// Size: 380 bytes

void FUN_801d45e4(undefined2 *param_1)

{
  uint uVar1;
  int iVar2;
  int iVar3;
  
  iVar3 = *(int *)(param_1 + 0x26);
  *param_1 = (short)((int)*(char *)(iVar3 + 0x18) << 8);
  if (((int)*(short *)(iVar3 + 0x20) == 0xffffffff) ||
     (uVar1 = FUN_80020078((int)*(short *)(iVar3 + 0x20)), uVar1 != 0)) {
    uVar1 = FUN_80020078(0x66c);
    if (uVar1 == 0) {
      *(byte *)((int)param_1 + 0xaf) = *(byte *)((int)param_1 + 0xaf) | 0x10;
    }
    else {
      *(byte *)((int)param_1 + 0xaf) = *(byte *)((int)param_1 + 0xaf) & 0xef;
    }
    iVar2 = FUN_8003809c((int)param_1,0x66c);
    if (iVar2 == 0) {
      if (((*(byte *)((int)param_1 + 0xaf) & 4) != 0) && (uVar1 = FUN_80020078(0x196), uVar1 == 0))
      {
        (**(code **)(*DAT_803dd6d4 + 0x48))(0,param_1,0xffffffff);
        FUN_800201ac(0x196,1);
      }
    }
    else {
      FUN_8001ffac(0x66c);
      FUN_800201ac((int)*(short *)(iVar3 + 0x1e),1);
      (**(code **)(*DAT_803dd6d4 + 0x48))(1,param_1,0xffffffff);
    }
    uVar1 = FUN_80020078((int)*(short *)(iVar3 + 0x1e));
    if (uVar1 == 0) {
      *(byte *)((int)param_1 + 0xaf) = *(byte *)((int)param_1 + 0xaf) & 0xf7;
      FUN_80041110();
    }
    else {
      *(byte *)((int)param_1 + 0xaf) = *(byte *)((int)param_1 + 0xaf) | 8;
    }
  }
  else {
    *(byte *)((int)param_1 + 0xaf) = *(byte *)((int)param_1 + 0xaf) | 8;
  }
  return;
}

