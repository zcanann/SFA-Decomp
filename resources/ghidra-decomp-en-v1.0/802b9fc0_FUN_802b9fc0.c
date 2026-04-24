// Function: FUN_802b9fc0
// Entry: 802b9fc0
// Size: 532 bytes

undefined4 FUN_802b9fc0(int param_1,uint *param_2)

{
  float fVar1;
  int iVar2;
  undefined4 uVar3;
  int iVar4;
  float local_18 [2];
  
  local_18[0] = FLOAT_803e8240;
  iVar2 = FUN_80036e58(0x13,param_1,local_18);
  iVar4 = *(int *)(param_1 + 0xb8);
  *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) | 8;
  fVar1 = FLOAT_803e8234;
  param_2[0xa5] = (uint)FLOAT_803e8234;
  param_2[0xa1] = (uint)fVar1;
  param_2[0xa0] = (uint)fVar1;
  *(float *)(param_1 + 0x24) = fVar1;
  *(float *)(param_1 + 0x28) = fVar1;
  *(float *)(param_1 + 0x2c) = fVar1;
  *param_2 = *param_2 | 0x200000;
  if (*(char *)((int)param_2 + 0x27a) != '\0') {
    *(undefined2 *)(param_2 + 0xce) = 0;
    param_2[0xa8] = (uint)FLOAT_803e827c;
    param_2[0xae] = (uint)FLOAT_803e8284;
    if ((int)*(short *)(param_1 + 0xa0) != (int)DAT_803dc748) {
      FUN_80030334(param_1,(int)DAT_803dc748,0);
    }
  }
  if (((*(short *)(param_1 + 0xa0) < 0x20b) && (0x208 < *(short *)(param_1 + 0xa0))) &&
     (*(char *)((int)param_2 + 0x346) != '\0')) {
    FUN_80030334((double)FLOAT_803e8234,param_1,(int)DAT_803dc748,0);
    param_2[0xa8] = (uint)FLOAT_803e827c;
  }
  if ((float)param_2[0xa6] < FLOAT_803e824c) {
    *(undefined2 *)(param_2 + 0xcd) = 0;
    *(undefined2 *)((int)param_2 + 0x336) = 0;
    param_2[0xa6] = (uint)FLOAT_803e8234;
  }
  if ((((float)param_2[0xa7] <= FLOAT_803e8234) || ((float)param_2[0xa6] <= FLOAT_803e8234)) ||
     (*(short *)(param_2 + 0xcd) < *(short *)(iVar4 + 0xa86))) {
    if ((((float)param_2[0xa7] <= FLOAT_803e8288) || ((float)param_2[0xa6] <= FLOAT_803e8288)) ||
       (*(short *)(iVar4 + 0xa86) <= *(short *)(param_2 + 0xcd))) {
      if (((param_2[199] & 0x100) == 0) || ((iVar2 != 0 && ((*(byte *)(iVar2 + 0xaf) & 4) != 0)))) {
        iVar2 = FUN_8001ffb4(0x3e3);
        if ((iVar2 != 0) &&
           (iVar2 = FUN_8002208c((double)FLOAT_803e8244,(double)FLOAT_803e8248,iVar4 + 0xd04),
           iVar2 != 0)) {
          FUN_8000bb18(param_1,0x43a);
        }
        uVar3 = 0;
      }
      else {
        uVar3 = 0xc;
      }
    }
    else {
      uVar3 = 0xb;
    }
  }
  else {
    uVar3 = 10;
  }
  return uVar3;
}

