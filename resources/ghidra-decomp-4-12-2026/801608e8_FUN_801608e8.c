// Function: FUN_801608e8
// Entry: 801608e8
// Size: 208 bytes

undefined4
FUN_801608e8(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
            undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,uint param_9
            ,int param_10,undefined4 param_11,undefined4 param_12,undefined4 param_13,
            undefined4 param_14,undefined4 param_15,undefined4 param_16)

{
  int iVar1;
  undefined4 uVar2;
  
  if (*(char *)(param_10 + 0x27b) == '\0') {
    iVar1 = FUN_8002bac4();
    FUN_800379bc(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,iVar1,0xe0000,
                 param_9,0,param_13,param_14,param_15,param_16);
    if (*(int *)(param_9 + 0x4c) == 0) {
      FUN_8002cc9c(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9);
      uVar2 = 0;
    }
    else {
      uVar2 = 4;
    }
  }
  else {
    (**(code **)(*DAT_803dd70c + 0x14))(param_9,param_10,3);
    *(undefined4 *)(param_10 + 0x2d0) = 0;
    *(undefined *)(param_10 + 0x25f) = 0;
    *(undefined *)(param_10 + 0x349) = 0;
    *(ushort *)(*(int *)(param_9 + 0x54) + 0x60) =
         *(ushort *)(*(int *)(param_9 + 0x54) + 0x60) & 0xfffe;
    *(byte *)(param_9 + 0xaf) = *(byte *)(param_9 + 0xaf) | 8;
    uVar2 = 0;
  }
  return uVar2;
}

