// Function: FUN_801dde74
// Entry: 801dde74
// Size: 412 bytes

void FUN_801dde74(undefined2 *param_1,int param_2)

{
  float fVar1;
  undefined4 *puVar2;
  uint uVar3;
  float *pfVar4;
  undefined8 local_18;
  
  pfVar4 = *(float **)(param_1 + 0x5c);
  *(undefined *)((int)param_1 + 0xad) = *(undefined *)(param_2 + 0x1b);
  if ((*(char *)((int)param_1 + 0xad) < '\0') || ('\x05' < *(char *)((int)param_1 + 0xad))) {
    *(undefined *)((int)param_1 + 0xad) = 0;
  }
  if ((*(char *)((int)param_1 + 0xad) == '\x05') &&
     (puVar2 = (undefined4 *)FUN_800395a4((int)param_1,0), puVar2 != (undefined4 *)0x0)) {
    *puVar2 = 0x100;
  }
  *(short *)(pfVar4 + 4) = (short)*(char *)((int)param_1 + 0xad);
  uVar3 = FUN_80020078(0x639);
  if (uVar3 == 0) {
    local_18 = (double)CONCAT44(0x43300000,
                                (int)*(short *)(&DAT_80328658 + *(short *)(pfVar4 + 4) * 2) ^
                                0x80000000);
    pfVar4[3] = (float)(local_18 - DOUBLE_803e62a8);
  }
  else {
    pfVar4[3] = FLOAT_803e62c4;
    puVar2 = (undefined4 *)FUN_800395a4((int)param_1,0);
    if (puVar2 != (undefined4 *)0x0) {
      *puVar2 = 0x100;
    }
  }
  *param_1 = (short)(int)pfVar4[3];
  uVar3 = FUN_80022264(7,10);
  fVar1 = FLOAT_803e62c8 *
          (float)((double)CONCAT44(0x43300000,uVar3 ^ 0x80000000) - DOUBLE_803e62a8);
  pfVar4[1] = fVar1;
  *pfVar4 = fVar1;
  if ((*(byte *)((int)param_1 + 0xad) & 1) != 0) {
    *(undefined2 *)((int)pfVar4 + 0x12) = 1;
  }
  pfVar4[2] = FLOAT_803e6294;
  *(code **)(param_1 + 0x5e) = FUN_801dd760;
  param_1[0x58] = param_1[0x58] | 0x6000;
  return;
}

