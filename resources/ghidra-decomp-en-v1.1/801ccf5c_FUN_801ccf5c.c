// Function: FUN_801ccf5c
// Entry: 801ccf5c
// Size: 132 bytes

void FUN_801ccf5c(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9)

{
  undefined4 in_r9;
  undefined4 in_r10;
  int iVar1;
  
  iVar1 = *(int *)(param_9 + 0xb8);
  if ((*(byte *)(iVar1 + 0x36) & 2) == 0) {
    FUN_800066e0(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9,param_9,1,0
                 ,0,0,in_r9,in_r10);
    *(byte *)(iVar1 + 0x36) = *(byte *)(iVar1 + 0x36) | 2;
  }
  (**(code **)(*DAT_803dd6f8 + 0x18))(param_9);
  return;
}

