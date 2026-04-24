// Function: FUN_801e9c74
// Entry: 801e9c74
// Size: 408 bytes

void FUN_801e9c74(undefined2 *param_1,int param_2)

{
  uint uVar1;
  int iVar2;
  float *pfVar3;
  double dVar4;
  
  pfVar3 = *(float **)(param_1 + 0x5c);
  param_1[0x58] = param_1[0x58] | 0x2000;
  param_1[0x58] = param_1[0x58] | 0x4000;
  *param_1 = (short)((int)*(char *)(param_2 + 0x18) << 8);
  if ((int)*(short *)(param_2 + 0x1a) != 0) {
    *(float *)(param_1 + 4) =
         FLOAT_803e6758 *
         ((float)((double)CONCAT44(0x43300000,(int)*(short *)(param_2 + 0x1a) ^ 0x80000000) -
                 DOUBLE_803e6768) / FLOAT_803e675c);
  }
  *pfVar3 = FLOAT_803e6754;
  dVar4 = (double)FUN_802945e0();
  pfVar3[1] = (float)dVar4;
  dVar4 = (double)FUN_80294964();
  pfVar3[2] = (float)dVar4;
  pfVar3[3] = -(pfVar3[1] * *(float *)(param_1 + 6) + pfVar3[2] * *(float *)(param_1 + 10));
  uVar1 = FUN_80022264(0xb4,300);
  *(short *)(pfVar3 + 5) = (short)uVar1;
  iVar2 = FUN_8002bac4();
  if (iVar2 != 0) {
    if (FLOAT_803e6738 <=
        pfVar3[3] + pfVar3[1] * *(float *)(iVar2 + 0xc) + pfVar3[2] * *(float *)(iVar2 + 0x14)) {
      pfVar3[4] = (float)&DAT_803dcd1c;
    }
    else {
      pfVar3[4] = (float)&DAT_803dcd18;
    }
  }
  return;
}

