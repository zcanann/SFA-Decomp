// Function: FUN_80235e90
// Entry: 80235e90
// Size: 708 bytes

void FUN_80235e90(short *param_1,int param_2)

{
  short sVar1;
  float fVar2;
  int iVar3;
  undefined auStack56 [32];
  double local_18;
  
  iVar3 = *(int *)(param_1 + 0x5c);
  *(float *)(iVar3 + 0x44) = FLOAT_803e730c;
  fVar2 = FLOAT_803e72f8;
  *(float *)(iVar3 + 0x40) = FLOAT_803e72f8;
  *(ushort *)(iVar3 + 0x54) = (ushort)*(byte *)(param_2 + 0x1d) << 1;
  *(ushort *)(iVar3 + 0x58) = (ushort)*(byte *)(param_2 + 0x1e);
  *(short *)(iVar3 + 0x58) = *(short *)(iVar3 + 0x58) << 8;
  *(ushort *)(iVar3 + 0x58) = *(ushort *)(iVar3 + 0x58) | (ushort)*(byte *)(param_2 + 0x1c);
  *(float *)(iVar3 + 0x3c) = fVar2;
  param_1[2] = (ushort)*(byte *)(param_2 + 0x18) << 8;
  param_1[1] = (ushort)*(byte *)(param_2 + 0x19) << 8;
  *param_1 = (ushort)*(byte *)(param_2 + 0x1a) << 8;
  *(byte *)((int)param_1 + 0xaf) = *(byte *)((int)param_1 + 0xaf) | 8;
  param_1[0x58] = param_1[0x58] | 0x2000;
  *(undefined4 *)(param_1 + 0x7c) = 0;
  if (*(byte *)(param_2 + 0x1b) == 0) {
    *(float *)(iVar3 + 0x48) = FLOAT_803e7308;
  }
  else {
    local_18 = (double)CONCAT44(0x43300000,(uint)*(byte *)(param_2 + 0x1b));
    *(float *)(iVar3 + 0x48) = (float)(local_18 - DOUBLE_803e7330) / FLOAT_803e7328;
    *(undefined4 *)(param_1 + 4) = *(undefined4 *)(iVar3 + 0x48);
    if (*(float *)(param_1 + 4) == fVar2) {
      *(float *)(param_1 + 4) = FLOAT_803e7308;
    }
    *(float *)(param_1 + 4) = *(float *)(param_1 + 4) * *(float *)(*(int *)(param_1 + 0x28) + 4);
  }
  FUN_80030334((double)FLOAT_803e72f8,param_1,0,0);
  FUN_8002fa48((double)FLOAT_803e7308,(double)FLOAT_803e7308,param_1,auStack56);
  if ((*(ushort *)(iVar3 + 0x58) & 0x80) != 0) {
    *(ushort *)(iVar3 + 0x58) = *(ushort *)(iVar3 + 0x58) | 0x20;
  }
  sVar1 = param_1[0x23];
  if (sVar1 == 0x625) {
    *(undefined2 *)(iVar3 + 0x5a) = 6;
    goto LAB_80236124;
  }
  if (sVar1 < 0x625) {
    if (sVar1 == 0x10b) {
      *(undefined2 *)(iVar3 + 0x5a) = 2;
      goto LAB_80236124;
    }
    if (sVar1 < 0x10b) {
      if (sVar1 == 0x39) {
        *(undefined2 *)(iVar3 + 0x5a) = 3;
        goto LAB_80236124;
      }
    }
    else {
      if (sVar1 == 0x5d1) {
        *(undefined2 *)(iVar3 + 0x5a) = 1;
        goto LAB_80236124;
      }
      if ((0x5d0 < sVar1) && (0x623 < sVar1)) {
        *(undefined2 *)(iVar3 + 0x5a) = 4;
        goto LAB_80236124;
      }
    }
  }
  else {
    if (sVar1 == 0x77a) {
      *(undefined2 *)(iVar3 + 0x5a) = 5;
      goto LAB_80236124;
    }
    if (sVar1 < 0x77a) {
      if (sVar1 == 0x70d) {
        *(undefined2 *)(iVar3 + 0x5a) = 8;
        goto LAB_80236124;
      }
      if ((sVar1 < 0x70d) && (0x70b < sVar1)) {
        *(undefined2 *)(iVar3 + 0x5a) = 7;
        local_18 = (double)(longlong)(int)(FLOAT_803e732c * *(float *)(param_1 + 4));
        FUN_80035b50(param_1,(int)(FLOAT_803e732c * *(float *)(param_1 + 4)),0xfffffffb,100);
        goto LAB_80236124;
      }
    }
    else {
      if (sVar1 == 0x799) {
        *(undefined2 *)(iVar3 + 0x5a) = 9;
        goto LAB_80236124;
      }
      if ((sVar1 < 0x799) && (0x797 < sVar1)) {
        *(undefined2 *)(iVar3 + 0x5a) = 10;
        goto LAB_80236124;
      }
    }
  }
  *(undefined2 *)(iVar3 + 0x5a) = 0;
LAB_80236124:
  if ((*(ushort *)(iVar3 + 0x58) & 0x20) == 0) {
    FUN_80035f00(param_1);
  }
  return;
}

