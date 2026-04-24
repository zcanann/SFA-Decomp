// Function: FUN_8013f314
// Entry: 8013f314
// Size: 372 bytes

void FUN_8013f314(undefined8 param_1,undefined8 param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined4 param_9,int param_10,int param_11,undefined4 param_12,byte param_13,
                 uint param_14,undefined4 param_15,undefined4 param_16)

{
  int iVar1;
  uint uVar2;
  double dVar3;
  double dVar4;
  
  iVar1 = FUN_80021850();
  if (*(char *)(param_10 + 10) == '\0') {
    uVar2 = FUN_80022264(0,1);
    *(uint *)(param_10 + 0x700) = uVar2;
    if (*(int *)(param_10 + 0x700) == 0) {
      *(undefined4 *)(param_10 + 0x700) = 0xffffffff;
    }
    *(int *)(param_10 + 0x704) = iVar1;
    *(undefined *)(param_10 + 10) = 1;
  }
  iVar1 = iVar1 - (*(uint *)(param_10 + 0x704) & 0xffff);
  if (0x8000 < iVar1) {
    iVar1 = iVar1 + -0xffff;
  }
  if (iVar1 < -0x8000) {
    iVar1 = iVar1 + 0xffff;
  }
  if (iVar1 < 0) {
    iVar1 = -iVar1;
  }
  if (iVar1 < 0x2000) {
    *(int *)(param_10 + 0x704) = *(int *)(param_10 + 0x704) + *(int *)(param_10 + 0x700) * 0x800;
  }
  dVar3 = (double)FUN_80293bc4();
  *(float *)(param_10 + 0x708) =
       -(float)((double)FLOAT_803e3164 * dVar3 -
               (double)*(float *)(*(int *)(param_10 + 0x24) + 0x18));
  *(undefined4 *)(param_10 + 0x70c) = *(undefined4 *)(*(int *)(param_10 + 0x24) + 0x1c);
  dVar3 = (double)FUN_802940dc();
  dVar4 = (double)FLOAT_803e3164;
  *(float *)(param_10 + 0x710) =
       -(float)(dVar4 * dVar3 - (double)*(float *)(*(int *)(param_10 + 0x24) + 0x20));
  iVar1 = FUN_8013b6f0((double)FLOAT_803e3118,dVar4,param_3,param_4,param_5,param_6,param_7,param_8,
                       param_9,param_10,param_11,param_12,param_13,param_14,param_15,param_16);
  if (iVar1 == 0) {
    FUN_80148fa0();
  }
  return;
}

