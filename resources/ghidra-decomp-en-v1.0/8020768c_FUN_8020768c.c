// Function: FUN_8020768c
// Entry: 8020768c
// Size: 700 bytes

void FUN_8020768c(short *param_1)

{
  int iVar1;
  char cVar2;
  short sVar3;
  int iVar4;
  short sVar5;
  int *piVar6;
  short local_38;
  undefined2 local_36;
  undefined2 local_34;
  float local_30;
  float local_2c;
  float local_28;
  float local_24;
  undefined4 local_20;
  uint uStack28;
  longlong local_18;
  
  iVar4 = *(int *)(param_1 + 0x5c);
  if ((((*(byte *)(iVar4 + 8) >> 4 & 1) != 0) && ((*(byte *)(iVar4 + 8) >> 5 & 1) == 0)) &&
     (0x32 < *(short *)(iVar4 + 4))) {
    FUN_8000da58(param_1,0x459);
    cVar2 = (**(code **)(*DAT_803dcaac + 0x40))((int)*(char *)(param_1 + 0x56));
    if (cVar2 == '\x02') {
      uStack28 = (uint)*(byte *)(iVar4 + 7);
      local_20 = 0x43300000;
      iVar1 = (int)((FLOAT_803e6458 +
                    (float)((double)CONCAT44(0x43300000,uStack28) - DOUBLE_803e6470)) *
                   FLOAT_803e645c * FLOAT_803db414);
      local_18 = (longlong)iVar1;
      *param_1 = *param_1 + (short)iVar1;
    }
    else {
      local_18 = (longlong)(int)(FLOAT_803e645c * FLOAT_803db414);
      *param_1 = *param_1 + (short)(int)(FLOAT_803e645c * FLOAT_803db414);
    }
  }
  if ((*(short *)(iVar4 + 4) != 0) && ((*(byte *)(iVar4 + 8) >> 4 & 1) != 0)) {
    local_18 = (longlong)(int)FLOAT_803db414;
    *(short *)(iVar4 + 4) = *(short *)(iVar4 + 4) - (short)(int)FLOAT_803db414;
    if (*(short *)(iVar4 + 4) < 1) {
      *(undefined2 *)(iVar4 + 4) = 200;
    }
  }
  local_2c = FLOAT_803e6460;
  local_28 = FLOAT_803e6460;
  local_24 = FLOAT_803e6460;
  local_30 = FLOAT_803e6458;
  sVar5 = 0;
  local_34 = 0;
  local_36 = 0;
  piVar6 = &DAT_803ad138;
  for (sVar3 = 0; sVar3 < 4; sVar3 = sVar3 + 1) {
    if (*piVar6 != 0) {
      *(float *)(*piVar6 + 0xc) = FLOAT_803e6460;
      *(float *)(*piVar6 + 0x10) = FLOAT_803e6464;
      *(float *)(*piVar6 + 0x14) = FLOAT_803e6468;
      local_38 = *param_1 + sVar5;
      FUN_80021ac8(&local_38,*piVar6 + 0xc);
      *(float *)(*piVar6 + 0xc) = *(float *)(*piVar6 + 0xc) + *(float *)(param_1 + 6);
      *(float *)(*piVar6 + 0x10) = *(float *)(*piVar6 + 0x10) + *(float *)(param_1 + 8);
      *(float *)(*piVar6 + 0x14) = *(float *)(*piVar6 + 0x14) + *(float *)(param_1 + 10);
    }
    if (piVar6[1] != 0) {
      *(float *)(piVar6[1] + 0xc) = FLOAT_803e6460;
      *(float *)(piVar6[1] + 0x10) = FLOAT_803e6464;
      *(float *)(piVar6[1] + 0x14) = FLOAT_803e6468;
      local_38 = *param_1 + sVar5;
      FUN_80021ac8(&local_38,piVar6[1] + 0xc);
      *(float *)(piVar6[1] + 0xc) = *(float *)(piVar6[1] + 0xc) + *(float *)(param_1 + 6);
      *(float *)(piVar6[1] + 0x10) = *(float *)(piVar6[1] + 0x10) + *(float *)(param_1 + 8);
      *(float *)(piVar6[1] + 0x14) = *(float *)(piVar6[1] + 0x14) + *(float *)(param_1 + 10);
    }
    piVar6 = piVar6 + 2;
    sVar5 = sVar5 + 0x3fff;
  }
  return;
}

