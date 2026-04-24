// Function: FUN_801a0614
// Entry: 801a0614
// Size: 368 bytes

undefined4 FUN_801a0614(int param_1,undefined4 param_2,int param_3)

{
  int iVar1;
  int iVar2;
  undefined4 local_28;
  undefined auStack36 [4];
  int local_20 [5];
  
  local_28 = 0;
  iVar2 = *(int *)(param_1 + 0x4c);
  iVar1 = FUN_8001ffb4((int)*(short *)(iVar2 + 0x18));
  if (iVar1 == 0) {
    if (*(short *)(param_1 + 0x46) != 0x127) {
      while (iVar1 = FUN_800374ec(param_1,local_20,auStack36,&local_28), iVar1 != 0) {
        if (local_20[0] == 0xa0005) {
          FUN_800200e8((int)*(short *)(iVar2 + 0x18),1);
        }
      }
      iVar1 = FUN_8001ffb4(0x44);
      if (iVar1 == 0) {
        *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) | 0x10;
      }
      else {
        *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) & 0xef;
      }
      if (((*(byte *)(param_1 + 0xaf) & 1) != 0) &&
         (iVar1 = (**(code **)(*DAT_803dca68 + 0x20))(0x44), iVar1 != 0)) {
        *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) | 8;
        (**(code **)(*DAT_803dca54 + 0x48))(0,param_1,0xffffffff);
      }
    }
  }
  else {
    *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) | 8;
    *(byte *)(param_3 + 0x90) = *(byte *)(param_3 + 0x90) | 4;
  }
  return 0;
}

