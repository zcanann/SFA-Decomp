// Function: FUN_801ad684
// Entry: 801ad684
// Size: 344 bytes

void FUN_801ad684(undefined2 *param_1,int param_2)

{
  char cVar1;
  undefined2 uVar2;
  float *pfVar3;
  
  *(undefined4 *)(param_1 + 0x7a) = 0;
  *param_1 = (short)((int)*(char *)(param_2 + 0x18) << 8);
  *(code **)(param_1 + 0x5e) = FUN_801ad440;
  if (param_1[0x23] == 0x172) {
    return;
  }
  pfVar3 = *(float **)(param_1 + 0x5c);
  uVar2 = FUN_800221a0(200,600);
  *(undefined2 *)(pfVar3 + 1) = uVar2;
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
        *pfVar3 = FLOAT_803e4740;
        goto LAB_801ad7ac;
      }
      if (-1 < cVar1) {
        *(undefined2 *)((int)pfVar3 + 6) = 0x92;
        *(undefined2 *)(pfVar3 + 2) = 0x93;
        *pfVar3 = FLOAT_803e4740;
        goto LAB_801ad7ac;
      }
    }
    else if (cVar1 < '\x04') {
      *(undefined2 *)((int)pfVar3 + 6) = 0x187;
      *(undefined2 *)(pfVar3 + 2) = 5;
      *pfVar3 = FLOAT_803e4740;
      goto LAB_801ad7ac;
    }
  }
  *(undefined2 *)((int)pfVar3 + 6) = 0x94;
  *(undefined2 *)(pfVar3 + 2) = 0x95;
  *pfVar3 = FLOAT_803e4744;
LAB_801ad7ac:
  *(undefined2 *)(pfVar3 + 4) = 0x12d;
  return;
}

