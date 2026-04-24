// Function: FUN_801a0b90
// Entry: 801a0b90
// Size: 368 bytes

undefined4 FUN_801a0b90(int param_1,undefined4 param_2,int param_3)

{
  uint uVar1;
  int iVar2;
  int iVar3;
  uint local_28;
  uint uStack_24;
  uint local_20 [5];
  
  local_28 = 0;
  iVar3 = *(int *)(param_1 + 0x4c);
  uVar1 = FUN_80020078((int)*(short *)(iVar3 + 0x18));
  if (uVar1 == 0) {
    if (*(short *)(param_1 + 0x46) != 0x127) {
      while (iVar2 = FUN_800375e4(param_1,local_20,&uStack_24,&local_28), iVar2 != 0) {
        if (local_20[0] == 0xa0005) {
          FUN_800201ac((int)*(short *)(iVar3 + 0x18),1);
        }
      }
      uVar1 = FUN_80020078(0x44);
      if (uVar1 == 0) {
        *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) | 0x10;
      }
      else {
        *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) & 0xef;
      }
      if (((*(byte *)(param_1 + 0xaf) & 1) != 0) &&
         (iVar3 = (**(code **)(*DAT_803dd6e8 + 0x20))(0x44), iVar3 != 0)) {
        *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) | 8;
        (**(code **)(*DAT_803dd6d4 + 0x48))(0,param_1,0xffffffff);
      }
    }
  }
  else {
    *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) | 8;
    *(byte *)(param_3 + 0x90) = *(byte *)(param_3 + 0x90) | 4;
  }
  return 0;
}

