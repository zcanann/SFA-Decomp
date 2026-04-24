// Function: FUN_801d3ff4
// Entry: 801d3ff4
// Size: 380 bytes

void FUN_801d3ff4(undefined2 *param_1)

{
  int iVar1;
  int iVar2;
  
  iVar2 = *(int *)(param_1 + 0x26);
  *param_1 = (short)((int)*(char *)(iVar2 + 0x18) << 8);
  if ((*(short *)(iVar2 + 0x20) == -1) || (iVar1 = FUN_8001ffb4(), iVar1 != 0)) {
    iVar1 = FUN_8001ffb4(0x66c);
    if (iVar1 == 0) {
      *(byte *)((int)param_1 + 0xaf) = *(byte *)((int)param_1 + 0xaf) | 0x10;
    }
    else {
      *(byte *)((int)param_1 + 0xaf) = *(byte *)((int)param_1 + 0xaf) & 0xef;
    }
    iVar1 = FUN_80037fa4(param_1,0x66c);
    if (iVar1 == 0) {
      if (((*(byte *)((int)param_1 + 0xaf) & 4) != 0) && (iVar1 = FUN_8001ffb4(0x196), iVar1 == 0))
      {
        (**(code **)(*DAT_803dca54 + 0x48))(0,param_1,0xffffffff);
        FUN_800200e8(0x196,1);
      }
    }
    else {
      FUN_8001fee8(0x66c);
      FUN_800200e8((int)*(short *)(iVar2 + 0x1e),1);
      (**(code **)(*DAT_803dca54 + 0x48))(1,param_1,0xffffffff);
    }
    iVar2 = FUN_8001ffb4((int)*(short *)(iVar2 + 0x1e));
    if (iVar2 == 0) {
      *(byte *)((int)param_1 + 0xaf) = *(byte *)((int)param_1 + 0xaf) & 0xf7;
      FUN_80041018(param_1);
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

