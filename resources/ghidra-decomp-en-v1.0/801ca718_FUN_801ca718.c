// Function: FUN_801ca718
// Entry: 801ca718
// Size: 304 bytes

undefined4 FUN_801ca718(undefined4 param_1,undefined4 param_2,int param_3)

{
  int iVar1;
  int iVar2;
  
  iVar1 = FUN_8002b9ec();
  if (iVar1 != 0) {
    for (iVar2 = 0; iVar2 < (int)(uint)*(byte *)(param_3 + 0x8b); iVar2 = iVar2 + 1) {
      if (*(char *)(param_3 + iVar2 + 0x81) == '\x01') {
        FUN_80296518(iVar1,0x10,1);
        FUN_800200e8(0x174,1);
        (**(code **)(*DAT_803dcaac + 0x50))(0xb,4,1);
        (**(code **)(*DAT_803dcaac + 0x50))(0xb,0x1d,1);
        (**(code **)(*DAT_803dcaac + 0x50))(0xb,0x1e,1);
        (**(code **)(*DAT_803dcaac + 0x50))(0xb,0x1f,1);
        (**(code **)(*DAT_803dcaac + 0x44))(0xb,6);
      }
    }
  }
  return 0;
}

