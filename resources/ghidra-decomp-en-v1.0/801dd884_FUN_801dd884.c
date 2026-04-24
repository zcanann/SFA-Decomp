// Function: FUN_801dd884
// Entry: 801dd884
// Size: 412 bytes

void FUN_801dd884(undefined2 *param_1,int param_2)

{
  float fVar1;
  undefined4 *puVar2;
  int iVar3;
  uint uVar4;
  float *pfVar5;
  double local_18;
  
  pfVar5 = *(float **)(param_1 + 0x5c);
  *(undefined *)((int)param_1 + 0xad) = *(undefined *)(param_2 + 0x1b);
  if ((*(char *)((int)param_1 + 0xad) < '\0') || ('\x05' < *(char *)((int)param_1 + 0xad))) {
    *(undefined *)((int)param_1 + 0xad) = 0;
  }
  if ((*(char *)((int)param_1 + 0xad) == '\x05') &&
     (puVar2 = (undefined4 *)FUN_800394ac(param_1,0,0), puVar2 != (undefined4 *)0x0)) {
    *puVar2 = 0x100;
  }
  *(short *)(pfVar5 + 4) = (short)*(char *)((int)param_1 + 0xad);
  iVar3 = FUN_8001ffb4(0x639);
  if (iVar3 == 0) {
    local_18 = (double)CONCAT44(0x43300000,
                                (int)*(short *)(&DAT_80327a18 + *(short *)(pfVar5 + 4) * 2) ^
                                0x80000000);
    pfVar5[3] = (float)(local_18 - DOUBLE_803e5610);
  }
  else {
    pfVar5[3] = FLOAT_803e562c;
    puVar2 = (undefined4 *)FUN_800394ac(param_1,0,0);
    if (puVar2 != (undefined4 *)0x0) {
      *puVar2 = 0x100;
    }
  }
  *param_1 = (short)(int)pfVar5[3];
  uVar4 = FUN_800221a0(7,10);
  fVar1 = FLOAT_803e5630 *
          (float)((double)CONCAT44(0x43300000,uVar4 ^ 0x80000000) - DOUBLE_803e5610);
  pfVar5[1] = fVar1;
  *pfVar5 = fVar1;
  if ((*(byte *)((int)param_1 + 0xad) & 1) != 0) {
    *(undefined2 *)((int)pfVar5 + 0x12) = 1;
  }
  pfVar5[2] = FLOAT_803e55fc;
  *(code **)(param_1 + 0x5e) = FUN_801dd170;
  param_1[0x58] = param_1[0x58] | 0x6000;
  return;
}

