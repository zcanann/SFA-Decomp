// Function: FUN_8017c82c
// Entry: 8017c82c
// Size: 292 bytes

undefined4
FUN_8017c82c(undefined8 param_1,double param_2,double param_3,undefined8 param_4,undefined8 param_5,
            undefined8 param_6,undefined8 param_7,undefined8 param_8,int param_9,undefined4 param_10
            ,int param_11,undefined4 param_12,int param_13,undefined4 param_14,undefined4 param_15,
            undefined4 param_16)

{
  byte bVar1;
  int iVar2;
  int iVar3;
  byte *pbVar4;
  int iVar5;
  
  if (*(short *)(param_9 + 0xb4) != -1) {
    iVar5 = *(int *)(param_9 + 0x4c);
    pbVar4 = *(byte **)(param_9 + 0xb8);
    *(undefined *)(param_11 + 0x56) = 0;
    iVar2 = param_11;
    for (iVar3 = 0; iVar3 < (int)(uint)*(byte *)(param_11 + 0x8b); iVar3 = iVar3 + 1) {
      bVar1 = *(byte *)(param_11 + iVar3 + 0x81);
      if (bVar1 == 2) {
        if (*(byte *)(iVar5 + 0x24) != 0) {
          param_1 = FUN_80055464(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                                 (uint)*(byte *)(iVar5 + 0x24),'\0',iVar2,param_12,param_13,param_14
                                 ,param_15,param_16);
        }
      }
      else if (bVar1 < 2) {
        if (((bVar1 != 0) && ((*(byte *)(iVar5 + 0x1d) & 1) == 0)) &&
           ((*(byte *)(iVar5 + 0x1d) & 2) != 0)) {
          param_1 = FUN_800201ac((int)*(short *)(iVar5 + 0x18),1);
        }
      }
      else if (bVar1 < 4) {
        iVar2 = 0;
        param_12 = 0;
        param_13 = *DAT_803dd6d4;
        param_1 = (**(code **)(param_13 + 0x50))(0x56,1);
      }
    }
    *pbVar4 = *pbVar4 | 4;
  }
  return 0;
}

