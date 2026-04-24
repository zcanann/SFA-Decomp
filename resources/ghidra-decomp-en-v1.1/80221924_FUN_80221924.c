// Function: FUN_80221924
// Entry: 80221924
// Size: 340 bytes

void FUN_80221924(undefined2 *param_1,int param_2)

{
  uint uVar1;
  float *pfVar2;
  double dVar3;
  
  FUN_800372f8((int)param_1,0x13);
  FUN_800372f8((int)param_1,0x39);
  *param_1 = (short)((int)*(char *)(param_2 + 0x18) << 8);
  pfVar2 = *(float **)(param_1 + 0x5c);
  dVar3 = (double)FUN_802945e0();
  *pfVar2 = (float)dVar3;
  pfVar2[1] = FLOAT_803e7890;
  dVar3 = (double)FUN_80294964();
  pfVar2[2] = (float)dVar3;
  pfVar2[3] = -(pfVar2[2] * *(float *)(param_1 + 10) +
               *pfVar2 * *(float *)(param_1 + 6) + pfVar2[1] * *(float *)(param_1 + 8));
  param_1[0x58] = param_1[0x58] | 0xe000;
  uVar1 = FUN_80020078(0x7a9);
  if ((int)*(char *)(param_2 + 0x19) == uVar1) {
    (**(code **)(*DAT_803dd72c + 0x50))((int)*(char *)(param_1 + 0x56),0xc,1);
  }
  return;
}

