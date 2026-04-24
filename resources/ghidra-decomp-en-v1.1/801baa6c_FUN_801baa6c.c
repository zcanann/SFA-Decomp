// Function: FUN_801baa6c
// Entry: 801baa6c
// Size: 216 bytes

undefined4
FUN_801baa6c(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
            undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,uint param_9
            ,int param_10,undefined4 param_11,undefined4 param_12,undefined4 param_13,
            undefined4 param_14,undefined4 param_15,undefined4 param_16)

{
  int iVar1;
  int iVar2;
  undefined8 uVar3;
  
  FUN_8002bac4();
  iVar2 = *(int *)(param_9 + 0xb8);
  if (*(char *)(param_10 + 0x27b) != '\0') {
    *(undefined4 *)(param_10 + 0x2d0) = 0;
    *(undefined *)(param_10 + 0x25f) = 0;
    *(undefined *)(param_10 + 0x349) = 0;
    uVar3 = FUN_80035ff8(param_9);
    *(byte *)(param_9 + 0xaf) = *(byte *)(param_9 + 0xaf) | 8;
    *(byte *)(param_9 + 0xaf) = *(byte *)(param_9 + 0xaf) & 0x7f;
    iVar1 = FUN_8002bac4();
    FUN_800379bc(uVar3,param_2,param_3,param_4,param_5,param_6,param_7,param_8,iVar1,0xe0000,param_9
                 ,0,param_13,param_14,param_15,param_16);
    FUN_800201ac((int)*(short *)(iVar2 + 0x3f4),0);
    uVar3 = FUN_800201ac((int)*(short *)(iVar2 + 0x3f2),1);
    if (*(int *)(param_9 + 0x4c) == 0) {
      FUN_8002cc9c(uVar3,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9);
    }
  }
  return 0;
}

