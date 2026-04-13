// Function: FUN_800132e0
// Entry: 800132e0
// Size: 372 bytes

int FUN_800132e0(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                undefined4 param_9,undefined4 param_10,undefined4 param_11,undefined4 param_12,
                undefined4 param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16)

{
  int iVar1;
  undefined4 extraout_r4;
  int *piVar2;
  undefined8 uVar3;
  uint local_18;
  int local_14;
  uint local_10 [2];
  
  iVar1 = FUN_80043680(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0x1a,param_9,
                       &local_18);
  if (iVar1 == 0) {
    FUN_8007d858();
    iVar1 = 0;
  }
  else {
    piVar2 = &local_14;
    uVar3 = FUN_80048ef4(local_18,local_10,piVar2);
    if ((int)local_10[0] < 1) {
      iVar1 = 0;
    }
    else if (local_14 < 0x7801) {
      if (local_14 < 1) {
        FUN_8007d858();
        iVar1 = 0;
      }
      else {
        iVar1 = FUN_80023d8c(local_14,0x10);
        if (iVar1 == 0) {
          FUN_8007d858();
          iVar1 = 0;
        }
        else {
          FUN_80046644(uVar3,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0x1b,iVar1,
                       local_18,local_10[0],(uint *)0x0,0,0,param_16);
          if (iVar1 == 0) {
            FUN_8007d858();
            iVar1 = 0;
          }
          else {
            *(int *)(iVar1 + 0x1c) = *(int *)(iVar1 + 0x1c) + iVar1;
            *(int *)(iVar1 + 0x24) = *(int *)(iVar1 + 0x24) + iVar1;
            *(int *)(iVar1 + 0x14) = *(int *)(iVar1 + 0x14) + iVar1;
            *(int *)(iVar1 + 0x20) = *(int *)(iVar1 + 0x20) + iVar1;
            *(int *)(iVar1 + 0x28) = *(int *)(iVar1 + 0x28) + iVar1;
            *(int *)(iVar1 + 0x18) = *(int *)(iVar1 + 0x18) + iVar1;
          }
        }
      }
    }
    else {
      FUN_80137c30(uVar3,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                   s_VOXMAP__Size_overflow_on_load_>I_802c69e4,extraout_r4,piVar2,param_12,param_13,
                   param_14,param_15,param_16);
      iVar1 = 0;
    }
  }
  return iVar1;
}

