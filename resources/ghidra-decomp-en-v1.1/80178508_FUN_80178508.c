// Function: FUN_80178508
// Entry: 80178508
// Size: 312 bytes

undefined4
FUN_80178508(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
            undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,int param_9,
            int param_10)

{
  float fVar1;
  short *psVar2;
  undefined4 uVar3;
  int iVar4;
  float *pfVar5;
  ushort local_28;
  short local_26;
  short local_24;
  float local_20;
  float local_1c;
  float local_18;
  float local_14;
  
  psVar2 = (short *)FUN_8002ba84();
  local_1c = FLOAT_803e42b0;
  if ((*(char *)(param_10 + 0x10) == '\0') && (psVar2 != (short *)0x0)) {
    *(float *)(param_9 + 0x24) = FLOAT_803e42b0;
    *(float *)(param_9 + 0x28) = local_1c;
    *(float *)(param_9 + 0x2c) = FLOAT_803e42b4;
    local_18 = local_1c;
    local_14 = local_1c;
    local_20 = FLOAT_803e42b8;
    local_24 = psVar2[2];
    local_26 = psVar2[1];
    iVar4 = FUN_80139318((int)psVar2);
    local_28 = *psVar2 + (short)iVar4;
    FUN_80021b8c(&local_28,(float *)(param_9 + 0x24));
    if ((psVar2[0x58] & 0x800U) == 0) {
      pfVar5 = (float *)(psVar2 + 6);
    }
    else {
      pfVar5 = (float *)FUN_80139324((int)psVar2);
    }
    fVar1 = FLOAT_803e42bc;
    *(float *)(param_10 + 4) = -(FLOAT_803e42bc * *(float *)(param_9 + 0x24) - *pfVar5);
    *(float *)(param_10 + 8) = -(fVar1 * *(float *)(param_9 + 0x28) - pfVar5[1]);
    *(float *)(param_10 + 0xc) = -(fVar1 * *(float *)(param_9 + 0x2c) - pfVar5[2]);
    if (*(char *)(param_10 + 0x11) == '\0') {
      FUN_80035ea4(param_9);
    }
    else {
      *(char *)(param_10 + 0x11) = *(char *)(param_10 + 0x11) + -1;
    }
    uVar3 = 1;
  }
  else {
    FUN_8002cc9c(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9);
    uVar3 = 0;
  }
  return uVar3;
}

