// Function: FUN_80161c18
// Entry: 80161c18
// Size: 276 bytes

bool FUN_80161c18(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 ushort *param_9,int param_10,undefined4 param_11,undefined4 param_12,
                 undefined4 param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16)

{
  ushort uVar1;
  float fVar2;
  int iVar3;
  
  iVar3 = *(int *)(*(int *)(param_9 + 0x5c) + 0x40c);
  if (*(char *)(param_10 + 0x27a) != '\0') {
    FUN_8003042c((double)FLOAT_803e3b50,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                 param_9,7,0,param_12,param_13,param_14,param_15,param_16);
    *(undefined *)(param_10 + 0x346) = 0;
  }
  if (*(char *)(param_10 + 0x27a) != '\0') {
    FUN_8000bb38((uint)param_9,0x27a);
  }
  *(float *)(param_10 + 0x2a0) = FLOAT_803e3b84;
  uVar1 = *(ushort *)(iVar3 + 0x58);
  iVar3 = (int)(short)*param_9 - (uint)uVar1;
  if (0x8000 < iVar3) {
    iVar3 = iVar3 + -0xffff;
  }
  if (iVar3 < -0x8000) {
    iVar3 = iVar3 + 0xffff;
  }
  *param_9 = uVar1;
  if ((0x3ffc < iVar3) || (iVar3 < -0x3ffc)) {
    *param_9 = *param_9 + 0x8000;
  }
  fVar2 = FLOAT_803e3b50;
  *(float *)(param_10 + 0x280) = FLOAT_803e3b50;
  *(float *)(param_10 + 0x284) = fVar2;
  return *(char *)(param_10 + 0x346) != '\0';
}

