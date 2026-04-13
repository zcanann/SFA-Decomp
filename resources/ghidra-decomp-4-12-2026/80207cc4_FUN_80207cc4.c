// Function: FUN_80207cc4
// Entry: 80207cc4
// Size: 700 bytes

void FUN_80207cc4(short *param_1)

{
  int iVar1;
  char cVar2;
  short sVar3;
  int iVar4;
  short sVar5;
  int *piVar6;
  ushort local_38 [4];
  float local_30;
  float local_2c;
  float local_28;
  float local_24;
  undefined4 local_20;
  uint uStack_1c;
  longlong local_18;
  
  iVar4 = *(int *)(param_1 + 0x5c);
  if ((((*(byte *)(iVar4 + 8) >> 4 & 1) != 0) && ((*(byte *)(iVar4 + 8) >> 5 & 1) == 0)) &&
     (0x32 < *(short *)(iVar4 + 4))) {
    FUN_8000da78((uint)param_1,0x459);
    cVar2 = (**(code **)(*DAT_803dd72c + 0x40))((int)*(char *)(param_1 + 0x56));
    if (cVar2 == '\x02') {
      uStack_1c = (uint)*(byte *)(iVar4 + 7);
      local_20 = 0x43300000;
      iVar1 = (int)((FLOAT_803e70f0 +
                    (float)((double)CONCAT44(0x43300000,uStack_1c) - DOUBLE_803e7108)) *
                   FLOAT_803e70f4 * FLOAT_803dc074);
      local_18 = (longlong)iVar1;
      *param_1 = *param_1 + (short)iVar1;
    }
    else {
      local_18 = (longlong)(int)(FLOAT_803e70f4 * FLOAT_803dc074);
      *param_1 = *param_1 + (short)(int)(FLOAT_803e70f4 * FLOAT_803dc074);
    }
  }
  if ((*(short *)(iVar4 + 4) != 0) && ((*(byte *)(iVar4 + 8) >> 4 & 1) != 0)) {
    local_18 = (longlong)(int)FLOAT_803dc074;
    *(short *)(iVar4 + 4) = *(short *)(iVar4 + 4) - (short)(int)FLOAT_803dc074;
    if (*(short *)(iVar4 + 4) < 1) {
      *(undefined2 *)(iVar4 + 4) = 200;
    }
  }
  local_2c = FLOAT_803e70f8;
  local_28 = FLOAT_803e70f8;
  local_24 = FLOAT_803e70f8;
  local_30 = FLOAT_803e70f0;
  sVar5 = 0;
  local_38[2] = 0;
  local_38[1] = 0;
  piVar6 = &DAT_803add98;
  for (sVar3 = 0; sVar3 < 4; sVar3 = sVar3 + 1) {
    if (*piVar6 != 0) {
      *(float *)(*piVar6 + 0xc) = FLOAT_803e70f8;
      *(float *)(*piVar6 + 0x10) = FLOAT_803e70fc;
      *(float *)(*piVar6 + 0x14) = FLOAT_803e7100;
      local_38[0] = *param_1 + sVar5;
      FUN_80021b8c(local_38,(float *)(*piVar6 + 0xc));
      *(float *)(*piVar6 + 0xc) = *(float *)(*piVar6 + 0xc) + *(float *)(param_1 + 6);
      *(float *)(*piVar6 + 0x10) = *(float *)(*piVar6 + 0x10) + *(float *)(param_1 + 8);
      *(float *)(*piVar6 + 0x14) = *(float *)(*piVar6 + 0x14) + *(float *)(param_1 + 10);
    }
    if (piVar6[1] != 0) {
      *(float *)(piVar6[1] + 0xc) = FLOAT_803e70f8;
      *(float *)(piVar6[1] + 0x10) = FLOAT_803e70fc;
      *(float *)(piVar6[1] + 0x14) = FLOAT_803e7100;
      local_38[0] = *param_1 + sVar5;
      FUN_80021b8c(local_38,(float *)(piVar6[1] + 0xc));
      *(float *)(piVar6[1] + 0xc) = *(float *)(piVar6[1] + 0xc) + *(float *)(param_1 + 6);
      *(float *)(piVar6[1] + 0x10) = *(float *)(piVar6[1] + 0x10) + *(float *)(param_1 + 8);
      *(float *)(piVar6[1] + 0x14) = *(float *)(piVar6[1] + 0x14) + *(float *)(param_1 + 10);
    }
    piVar6 = piVar6 + 2;
    sVar5 = sVar5 + 0x3fff;
  }
  return;
}

