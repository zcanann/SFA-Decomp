// Function: FUN_80221d94
// Entry: 80221d94
// Size: 488 bytes

void FUN_80221d94(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 uint param_9,undefined4 param_10,undefined4 param_11,int param_12,
                 undefined4 param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16)

{
  float fVar1;
  int iVar2;
  uint uVar3;
  undefined4 uVar4;
  int *piVar5;
  double dVar6;
  
  piVar5 = *(int **)(param_9 + 0xb8);
  iVar2 = FUN_8002bac4();
  uVar3 = FUN_80020078(0xadb);
  if ((uVar3 == 0) &&
     (dVar6 = (double)FUN_800217c8((float *)(param_9 + 0x18),(float *)(iVar2 + 0x18)),
     dVar6 < (double)FLOAT_803e78bc)) {
    param_12 = *DAT_803dd6d4;
    (**(code **)(param_12 + 0x48))(1,param_9,0xffffffff);
    FUN_800201ac(0xadb,1);
  }
  uVar3 = FUN_800803dc((float *)(piVar5 + 2));
  if (uVar3 != 0) {
    if (((float)piVar5[2] <= FLOAT_803e78c0) && (*(char *)(piVar5 + 1) == '\0')) {
      *(undefined *)(piVar5 + 1) = 1;
      FUN_8003042c((double)FLOAT_803e78c4,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                   param_9,0,0,param_12,param_13,param_14,param_15,param_16);
      FUN_8000bb38(param_9,0x328);
      *(undefined *)(piVar5 + 3) = 0;
    }
    iVar2 = FUN_80080434((float *)(piVar5 + 2));
    if ((iVar2 != 0) && (iVar2 = FUN_80037ad4(*piVar5), iVar2 != 0)) {
      iVar2 = *piVar5;
      *(undefined4 *)(iVar2 + 0xc) = *(undefined4 *)(param_9 + 0xc);
      *(undefined4 *)(iVar2 + 0x10) = *(undefined4 *)(param_9 + 0x10);
      *(undefined4 *)(iVar2 + 0x14) = *(undefined4 *)(param_9 + 0x14);
      *(undefined4 *)(iVar2 + 0x80) = *(undefined4 *)(iVar2 + 0xc);
      *(undefined4 *)(iVar2 + 0x84) = *(undefined4 *)(iVar2 + 0x10);
      *(undefined4 *)(iVar2 + 0x88) = *(undefined4 *)(iVar2 + 0x14);
      *(undefined4 *)(iVar2 + 0x18) = *(undefined4 *)(iVar2 + 0xc);
      *(undefined4 *)(iVar2 + 0x1c) = *(undefined4 *)(iVar2 + 0x10);
      *(undefined4 *)(iVar2 + 0x20) = *(undefined4 *)(iVar2 + 0x14);
      fVar1 = FLOAT_803e78c4;
      *(float *)(iVar2 + 0x2c) = FLOAT_803e78c4;
      *(float *)(iVar2 + 0x28) = fVar1;
      *(float *)(iVar2 + 0x24) = fVar1;
      FUN_800372f8(*piVar5,0x19);
      *piVar5 = 0;
    }
  }
  if (*(char *)(piVar5 + 1) != '\0') {
    if ((FLOAT_803e78c8 < *(float *)(param_9 + 0x98)) && (*(char *)(piVar5 + 3) == '\0')) {
      FUN_8000bb38(param_9,0x329);
      *(undefined *)(piVar5 + 3) = 1;
    }
    uVar4 = FUN_8002fb40((double)FLOAT_803e78cc,(double)FLOAT_803dc074);
    uVar3 = countLeadingZeros(uVar4);
    *(char *)(piVar5 + 1) = (char)(uVar3 >> 5);
  }
  return;
}

