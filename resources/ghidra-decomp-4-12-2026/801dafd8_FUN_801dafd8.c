// Function: FUN_801dafd8
// Entry: 801dafd8
// Size: 112 bytes

void FUN_801dafd8(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9,int param_10)

{
  int iVar1;
  int *piVar2;
  undefined8 uVar3;
  
  piVar2 = *(int **)(param_9 + 0xb8);
  uVar3 = (**(code **)(*DAT_803dd6f8 + 0x18))();
  if (((param_10 == 0) && (iVar1 = *piVar2, iVar1 != 0)) &&
     ((*(ushort *)(iVar1 + 0xb0) & 0x40) == 0)) {
    FUN_8002cc9c(uVar3,param_2,param_3,param_4,param_5,param_6,param_7,param_8,iVar1);
  }
  return;
}

