// Function: FUN_8017805c
// Entry: 8017805c
// Size: 312 bytes

undefined4 FUN_8017805c(int param_1,int param_2)

{
  float fVar1;
  short *psVar2;
  undefined4 uVar3;
  float *pfVar4;
  short local_28;
  short local_26;
  short local_24;
  float local_20;
  float local_1c;
  float local_18;
  float local_14;
  
  psVar2 = (short *)FUN_8002b9ac();
  local_1c = FLOAT_803e3618;
  if ((*(char *)(param_2 + 0x10) == '\0') && (psVar2 != (short *)0x0)) {
    *(float *)(param_1 + 0x24) = FLOAT_803e3618;
    *(float *)(param_1 + 0x28) = local_1c;
    *(float *)(param_1 + 0x2c) = FLOAT_803e361c;
    local_18 = local_1c;
    local_14 = local_1c;
    local_20 = FLOAT_803e3620;
    local_24 = psVar2[2];
    local_26 = psVar2[1];
    local_28 = FUN_80138f90();
    local_28 = *psVar2 + local_28;
    FUN_80021ac8(&local_28,param_1 + 0x24);
    if ((psVar2[0x58] & 0x800U) == 0) {
      pfVar4 = (float *)(psVar2 + 6);
    }
    else {
      pfVar4 = (float *)FUN_80138f9c(psVar2);
    }
    fVar1 = FLOAT_803e3624;
    *(float *)(param_2 + 4) = -(FLOAT_803e3624 * *(float *)(param_1 + 0x24) - *pfVar4);
    *(float *)(param_2 + 8) = -(fVar1 * *(float *)(param_1 + 0x28) - pfVar4[1]);
    *(float *)(param_2 + 0xc) = -(fVar1 * *(float *)(param_1 + 0x2c) - pfVar4[2]);
    if (*(char *)(param_2 + 0x11) == '\0') {
      FUN_80035dac(param_1);
    }
    else {
      *(char *)(param_2 + 0x11) = *(char *)(param_2 + 0x11) + -1;
    }
    uVar3 = 1;
  }
  else {
    FUN_8002cbc4(param_1);
    uVar3 = 0;
  }
  return uVar3;
}

