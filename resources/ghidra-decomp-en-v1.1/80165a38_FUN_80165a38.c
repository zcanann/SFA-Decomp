// Function: FUN_80165a38
// Entry: 80165a38
// Size: 1068 bytes

/* WARNING: Removing unreachable block (ram,0x80165e3c) */
/* WARNING: Removing unreachable block (ram,0x80165e34) */
/* WARNING: Removing unreachable block (ram,0x80165e2c) */
/* WARNING: Removing unreachable block (ram,0x80165e24) */
/* WARNING: Removing unreachable block (ram,0x80165a60) */
/* WARNING: Removing unreachable block (ram,0x80165a58) */
/* WARNING: Removing unreachable block (ram,0x80165a50) */
/* WARNING: Removing unreachable block (ram,0x80165a48) */
/* WARNING: Removing unreachable block (ram,0x80165c5c) */

undefined4
FUN_80165a38(undefined8 param_1,double param_2,double param_3,undefined8 param_4,undefined8 param_5,
            undefined8 param_6,undefined8 param_7,undefined8 param_8,short *param_9,uint *param_10,
            undefined4 param_11,undefined4 param_12,undefined4 param_13,undefined4 param_14,
            undefined4 param_15,undefined4 param_16)

{
  int iVar1;
  uint uVar2;
  int iVar3;
  double dVar4;
  double in_f28;
  double in_f29;
  double in_f30;
  double in_f31;
  
  iVar3 = *(int *)(*(int *)(param_9 + 0x5c) + 0x40c);
  iVar1 = FUN_8002bac4();
  *(undefined *)((int)param_10 + 0x34d) = 1;
  if (*(char *)((int)param_10 + 0x27a) != '\0') {
    *(float *)(iVar3 + 0x60) = FLOAT_803e3c9c;
    FUN_80036018((int)param_9);
    dVar4 = (double)FUN_80293bc4();
    *(float *)(param_9 + 0x12) = (float)(-(double)*(float *)(iVar3 + 0x60) * dVar4);
    *(float *)(param_9 + 0x14) = FLOAT_803e3c74;
    dVar4 = (double)FUN_802940dc();
    *(float *)(param_9 + 0x16) = (float)(-(double)*(float *)(iVar3 + 0x60) * dVar4);
    *param_10 = *param_10 | 0x2004000;
    FUN_8003042c((double)FLOAT_803e3c74,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                 param_9,0,0,param_12,param_13,param_14,param_15,param_16);
    *(float *)(iVar3 + 0x44) = FLOAT_803e3ca0;
  }
  FUN_80035eec((int)param_9,9,1,-1);
  *(undefined *)(*(int *)(param_9 + 0x2a) + 0x6c) = 9;
  *(undefined *)(*(int *)(param_9 + 0x2a) + 0x6d) = 1;
  FUN_80033a34(param_9);
  (**(code **)(*DAT_803dd728 + 0x18))((double)FLOAT_803dc074,param_9,param_10 + 1);
  if (*(char *)(iVar3 + 0x90) == '\x06') {
    if ((*(byte *)(iVar3 + 0x92) & 1) == 0) {
      uVar2 = 0;
    }
    else {
      uVar2 = 2;
      if ((ushort)DAT_803dc070 < *(ushort *)(iVar3 + 0x8e)) {
        *(ushort *)(iVar3 + 0x8e) = *(ushort *)(iVar3 + 0x8e) - (ushort)DAT_803dc070;
      }
      else {
        *(byte *)(iVar3 + 0x92) = *(byte *)(iVar3 + 0x92) & 0xfe;
      }
    }
  }
  else if ((((iVar1 == 0) || (*(float *)(iVar1 + 0x18) < *(float *)(iVar3 + 0x48))) ||
           (*(float *)(iVar3 + 0x4c) < *(float *)(iVar1 + 0x18))) ||
          (((*(float *)(iVar1 + 0x1c) < *(float *)(iVar3 + 0x5c) ||
            (*(float *)(iVar3 + 0x58) < *(float *)(iVar1 + 0x1c))) ||
           ((*(float *)(iVar1 + 0x20) < *(float *)(iVar3 + 0x54) ||
            (*(float *)(iVar3 + 0x50) < *(float *)(iVar1 + 0x20))))))) {
    uVar2 = 1;
  }
  else {
    uVar2 = 0;
  }
  if (uVar2 == 1) {
    if ((ushort)DAT_803dc070 < *(ushort *)(iVar3 + 0x8c)) {
      *(ushort *)(iVar3 + 0x8c) = *(ushort *)(iVar3 + 0x8c) - (ushort)DAT_803dc070;
    }
    else {
      uVar2 = FUN_80022264((int)*(float *)(iVar3 + 0x48),(int)*(float *)(iVar3 + 0x4c));
      *(float *)(iVar3 + 100) =
           (float)((double)CONCAT44(0x43300000,uVar2 ^ 0x80000000) - DOUBLE_803e3cb0);
      uVar2 = FUN_80022264((int)*(float *)(iVar3 + 0x5c),(int)*(float *)(iVar3 + 0x58));
      *(float *)(iVar3 + 0x68) =
           (float)((double)CONCAT44(0x43300000,uVar2 ^ 0x80000000) - DOUBLE_803e3cb0);
      uVar2 = FUN_80022264((int)*(float *)(iVar3 + 0x54),(int)*(float *)(iVar3 + 0x50));
      *(float *)(iVar3 + 0x6c) =
           (float)((double)CONCAT44(0x43300000,uVar2 ^ 0x80000000) - DOUBLE_803e3cb0);
      uVar2 = FUN_80022264(300,600);
      *(short *)(iVar3 + 0x8c) = (short)uVar2;
    }
    in_f31 = (double)*(float *)(iVar3 + 100);
    in_f30 = (double)*(float *)(iVar3 + 0x68);
    in_f29 = (double)*(float *)(iVar3 + 0x6c);
    in_f28 = (double)FLOAT_803e3ca8;
  }
  else if (uVar2 == 0) {
    in_f31 = (double)*(float *)(iVar1 + 0xc);
    in_f30 = (double)(*(float *)(iVar1 + 0x10) - FLOAT_803e3c70);
    in_f29 = (double)*(float *)(iVar1 + 0x14);
    in_f28 = (double)FLOAT_803e3ca4;
    uVar2 = FUN_80020078(0x698);
    if (uVar2 != 0) {
      in_f28 = -(double)FLOAT_803e3ca4;
    }
  }
  else if (uVar2 < 3) {
    in_f31 = (double)*(float *)(iVar3 + 0x70);
    in_f30 = (double)*(float *)(iVar3 + 0x74);
    in_f29 = (double)*(float *)(iVar3 + 0x78);
    in_f28 = (double)FLOAT_803e3ca4;
  }
  FUN_80166efc(in_f31,in_f30,in_f29,in_f28,(int)param_9);
  if (*(char *)(iVar3 + 0x90) == '\x06') {
    if ((*(byte *)(iVar3 + 0x92) >> 2 & 1) == 0) {
      FUN_801668f0((int)param_9,iVar3);
    }
    else {
      FUN_80165fe8((int)param_9,iVar3);
    }
  }
  else {
    FUN_80166138(param_9,iVar3);
  }
  return 0;
}

