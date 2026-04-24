// Function: FUN_80236554
// Entry: 80236554
// Size: 708 bytes

void FUN_80236554(undefined8 param_1,undefined8 param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 short *param_9,int param_10,undefined4 param_11,undefined4 param_12,
                 undefined4 param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16)

{
  short sVar1;
  float fVar2;
  int iVar3;
  double dVar4;
  undefined8 local_18;
  
  iVar3 = *(int *)(param_9 + 0x5c);
  *(float *)(iVar3 + 0x44) = FLOAT_803e7fa4;
  fVar2 = FLOAT_803e7f90;
  dVar4 = (double)FLOAT_803e7f90;
  *(float *)(iVar3 + 0x40) = FLOAT_803e7f90;
  *(ushort *)(iVar3 + 0x54) = (ushort)*(byte *)(param_10 + 0x1d) << 1;
  *(ushort *)(iVar3 + 0x58) = (ushort)*(byte *)(param_10 + 0x1e);
  *(short *)(iVar3 + 0x58) = *(short *)(iVar3 + 0x58) << 8;
  *(ushort *)(iVar3 + 0x58) = *(ushort *)(iVar3 + 0x58) | (ushort)*(byte *)(param_10 + 0x1c);
  *(float *)(iVar3 + 0x3c) = fVar2;
  param_9[2] = (ushort)*(byte *)(param_10 + 0x18) << 8;
  param_9[1] = (ushort)*(byte *)(param_10 + 0x19) << 8;
  *param_9 = (ushort)*(byte *)(param_10 + 0x1a) << 8;
  *(byte *)((int)param_9 + 0xaf) = *(byte *)((int)param_9 + 0xaf) | 8;
  param_9[0x58] = param_9[0x58] | 0x2000;
  param_9[0x7c] = 0;
  param_9[0x7d] = 0;
  if (*(byte *)(param_10 + 0x1b) == 0) {
    *(float *)(iVar3 + 0x48) = FLOAT_803e7fa0;
  }
  else {
    local_18 = (double)CONCAT44(0x43300000,(uint)*(byte *)(param_10 + 0x1b));
    *(float *)(iVar3 + 0x48) = (float)(local_18 - DOUBLE_803e7fc8) / FLOAT_803e7fc0;
    *(undefined4 *)(param_9 + 4) = *(undefined4 *)(iVar3 + 0x48);
    if ((double)*(float *)(param_9 + 4) == dVar4) {
      *(float *)(param_9 + 4) = FLOAT_803e7fa0;
    }
    *(float *)(param_9 + 4) = *(float *)(param_9 + 4) * *(float *)(*(int *)(param_9 + 0x28) + 4);
  }
  FUN_8003042c((double)FLOAT_803e7f90,dVar4,param_3,param_4,param_5,param_6,param_7,param_8,param_9,
               0,0,param_12,param_13,param_14,param_15,param_16);
  FUN_8002fb40((double)FLOAT_803e7fa0,(double)FLOAT_803e7fa0);
  if ((*(ushort *)(iVar3 + 0x58) & 0x80) != 0) {
    *(ushort *)(iVar3 + 0x58) = *(ushort *)(iVar3 + 0x58) | 0x20;
  }
  sVar1 = param_9[0x23];
  if (sVar1 == 0x625) {
    *(undefined2 *)(iVar3 + 0x5a) = 6;
    goto LAB_802367e8;
  }
  if (sVar1 < 0x625) {
    if (sVar1 == 0x10b) {
      *(undefined2 *)(iVar3 + 0x5a) = 2;
      goto LAB_802367e8;
    }
    if (sVar1 < 0x10b) {
      if (sVar1 == 0x39) {
        *(undefined2 *)(iVar3 + 0x5a) = 3;
        goto LAB_802367e8;
      }
    }
    else {
      if (sVar1 == 0x5d1) {
        *(undefined2 *)(iVar3 + 0x5a) = 1;
        goto LAB_802367e8;
      }
      if ((0x5d0 < sVar1) && (0x623 < sVar1)) {
        *(undefined2 *)(iVar3 + 0x5a) = 4;
        goto LAB_802367e8;
      }
    }
  }
  else {
    if (sVar1 == 0x77a) {
      *(undefined2 *)(iVar3 + 0x5a) = 5;
      goto LAB_802367e8;
    }
    if (sVar1 < 0x77a) {
      if (sVar1 == 0x70d) {
        *(undefined2 *)(iVar3 + 0x5a) = 8;
        goto LAB_802367e8;
      }
      if ((sVar1 < 0x70d) && (0x70b < sVar1)) {
        *(undefined2 *)(iVar3 + 0x5a) = 7;
        FUN_80035c48((int)param_9,(short)(int)(FLOAT_803e7fc4 * *(float *)(param_9 + 4)),-5,100);
        goto LAB_802367e8;
      }
    }
    else {
      if (sVar1 == 0x799) {
        *(undefined2 *)(iVar3 + 0x5a) = 9;
        goto LAB_802367e8;
      }
      if ((sVar1 < 0x799) && (0x797 < sVar1)) {
        *(undefined2 *)(iVar3 + 0x5a) = 10;
        goto LAB_802367e8;
      }
    }
  }
  *(undefined2 *)(iVar3 + 0x5a) = 0;
LAB_802367e8:
  if ((*(ushort *)(iVar3 + 0x58) & 0x20) == 0) {
    FUN_80035ff8((int)param_9);
  }
  return;
}

