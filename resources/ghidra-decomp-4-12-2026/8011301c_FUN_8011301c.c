// Function: FUN_8011301c
// Entry: 8011301c
// Size: 276 bytes

void FUN_8011301c(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined4 param_9,undefined4 param_10,int param_11,int param_12,
                 undefined *param_13,undefined4 param_14,undefined4 param_15,int param_16,
                 char param_17)

{
  undefined4 uVar1;
  int iVar2;
  int iVar3;
  undefined *puVar4;
  int iVar5;
  undefined8 uVar6;
  
  uVar6 = FUN_8028683c();
  uVar1 = (undefined4)((ulonglong)uVar6 >> 0x20);
  iVar2 = (int)uVar6;
  if (param_11 != 0) {
    *(undefined *)(param_11 + 0x24) = 0;
    *(undefined *)(param_11 + 0x25) = 0;
    *(undefined *)(param_11 + 0x26) = 4;
    *(undefined *)(param_11 + 0x27) = 0x14;
  }
  if ((short)param_14 != -1) {
    *(short *)(iVar2 + 0x270) = (short)param_14;
    *(undefined *)(iVar2 + 0x27b) = 1;
  }
  iVar3 = param_12;
  puVar4 = param_13;
  iVar5 = param_16;
  if ((short)param_15 != -1) {
    iVar3 = *DAT_803dd70c;
    (**(code **)(iVar3 + 0x14))(uVar1,iVar2);
  }
  if (param_13 != (undefined *)0x0) {
    *param_13 = 2;
  }
  if (param_16 != 0) {
    FUN_8003042c((double)FLOAT_803e28ac,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                 uVar1,param_16,0,iVar3,puVar4,param_14,param_15,iVar5);
  }
  (**(code **)(*DAT_803dd728 + 0x20))(uVar1,iVar2 + 4);
  if (param_17 != -1) {
    *(char *)(iVar2 + 0x25f) = param_17;
  }
  if ((int)(short)param_12 != 0xffffffff) {
    FUN_800201ac((int)(short)param_12,1);
  }
  FUN_80286888();
  return;
}

