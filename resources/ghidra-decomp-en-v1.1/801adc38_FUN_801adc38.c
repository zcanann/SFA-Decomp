// Function: FUN_801adc38
// Entry: 801adc38
// Size: 344 bytes

void FUN_801adc38(undefined2 *param_1,int param_2)

{
  char cVar1;
  uint uVar2;
  float *pfVar3;
  
  *(undefined4 *)(param_1 + 0x7a) = 0;
  *param_1 = (short)((int)*(char *)(param_2 + 0x18) << 8);
  *(code **)(param_1 + 0x5e) = FUN_801ad9f4;
  if (param_1[0x23] == 0x172) {
    return;
  }
  pfVar3 = *(float **)(param_1 + 0x5c);
  uVar2 = FUN_80022264(200,600);
  *(short *)(pfVar3 + 1) = (short)uVar2;
  *(char *)(pfVar3 + 3) = (char)*(undefined2 *)(param_2 + 0x1a);
  *(undefined *)((int)pfVar3 + 0xb) = 0;
  if (param_1[0x23] != 0x16b) {
    *(undefined2 *)(pfVar3 + 4) = 0x12d;
    return;
  }
  cVar1 = *(char *)(pfVar3 + 3);
  if (cVar1 != '\x02') {
    if (cVar1 < '\x02') {
      if (cVar1 == '\0') {
        *(undefined2 *)((int)pfVar3 + 6) = 0x90;
        *(undefined2 *)(pfVar3 + 2) = 0x91;
        *pfVar3 = FLOAT_803e53d8;
        goto LAB_801add60;
      }
      if (-1 < cVar1) {
        *(undefined2 *)((int)pfVar3 + 6) = 0x92;
        *(undefined2 *)(pfVar3 + 2) = 0x93;
        *pfVar3 = FLOAT_803e53d8;
        goto LAB_801add60;
      }
    }
    else if (cVar1 < '\x04') {
      *(undefined2 *)((int)pfVar3 + 6) = 0x187;
      *(undefined2 *)(pfVar3 + 2) = 5;
      *pfVar3 = FLOAT_803e53d8;
      goto LAB_801add60;
    }
  }
  *(undefined2 *)((int)pfVar3 + 6) = 0x94;
  *(undefined2 *)(pfVar3 + 2) = 0x95;
  *pfVar3 = FLOAT_803e53dc;
LAB_801add60:
  *(undefined2 *)(pfVar3 + 4) = 0x12d;
  return;
}

