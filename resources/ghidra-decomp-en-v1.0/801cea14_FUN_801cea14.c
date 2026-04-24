// Function: FUN_801cea14
// Entry: 801cea14
// Size: 788 bytes

void FUN_801cea14(short *param_1,int param_2,int param_3)

{
  byte bVar1;
  float fVar2;
  float fVar3;
  int iVar4;
  short sVar5;
  double dVar6;
  
  iVar4 = FUN_801ce078();
  if (iVar4 == 0) {
    if (((*(byte *)((int)param_1 + 0xaf) & 4) != 0) || (*(float *)(param_2 + 0x18) < FLOAT_803e5244)
       ) {
      *(float *)(param_2 + 0x54) = -(FLOAT_803e5248 * FLOAT_803db414 - *(float *)(param_2 + 0x54));
      if (*(float *)(param_2 + 0x54) < FLOAT_803e5240) {
        *(float *)(param_2 + 0x54) = FLOAT_803e520c;
      }
    }
    else {
      *(float *)(param_2 + 0x54) = FLOAT_803e523c * FLOAT_803db414 + *(float *)(param_2 + 0x54);
      if (FLOAT_803e524c < *(float *)(param_2 + 0x54)) {
        *(float *)(param_2 + 0x54) = FLOAT_803e524c;
      }
    }
  }
  else if (iVar4 < 0) {
    if ((-2 < iVar4) &&
       (*(float *)(param_2 + 0x54) = -(FLOAT_803e523c * FLOAT_803db414 - *(float *)(param_2 + 0x54))
       , *(float *)(param_2 + 0x54) < FLOAT_803e5240)) {
      *(float *)(param_2 + 0x54) = FLOAT_803e520c;
    }
  }
  else if (iVar4 < 2) {
    return;
  }
  bVar1 = *(byte *)(param_2 + 0x408);
  if (bVar1 == 8) {
    iVar4 = FUN_80010320((double)*(float *)(param_2 + 0x54),param_2 + 0x5c);
    if ((iVar4 != 0) || (*(int *)(param_2 + 0x6c) != 0)) {
      (**(code **)(*DAT_803dca9c + 0x90))(param_2 + 0x5c);
    }
    fVar2 = *(float *)(param_2 + 0xc4) - *(float *)(param_1 + 6);
    fVar3 = *(float *)(param_2 + 0xcc) - *(float *)(param_1 + 10);
    dVar6 = (double)FUN_802931a0((double)(fVar2 * fVar2 + fVar3 * fVar3));
    FUN_8002f5d4((double)(float)((double)FLOAT_803db418 * dVar6),param_1,param_2 + 0x4c);
    sVar5 = FUN_800217c0((double)*(float *)(param_2 + 0xd0),(double)*(float *)(param_2 + 0xd8));
    *param_1 = sVar5 + -0x8000;
    *(undefined4 *)(param_1 + 6) = *(undefined4 *)(param_2 + 0xc4);
    *(undefined4 *)(param_1 + 10) = *(undefined4 *)(param_2 + 0xcc);
    if (*(float *)(param_2 + 0x54) <= FLOAT_803e520c) {
      *(undefined *)(param_2 + 0x408) = 7;
    }
  }
  else if (((bVar1 < 8) && (6 < bVar1)) && (FLOAT_803e5250 < *(float *)(param_2 + 0x54))) {
    *(undefined *)(param_2 + 0x408) = 8;
  }
  if (*(char *)(param_3 + 0x1d) == '\x01') {
    iVar4 = FUN_8001ffb4(0x19d);
    if (iVar4 == 0) {
      iVar4 = FUN_8001ffb4(0x1a2);
      if (iVar4 == 0) {
        iVar4 = FUN_8001ffb4(0x102);
        if (iVar4 == 0) {
          iVar4 = FUN_8001ffb4(0x9e);
          if (iVar4 == 0) {
            *(undefined **)(param_2 + 0x48) = &DAT_803dbf80;
          }
          else {
            *(undefined **)(param_2 + 0x48) = &DAT_803dbf84;
          }
        }
        else {
          *(undefined **)(param_2 + 0x48) = &DAT_803dbf88;
        }
      }
      else {
        *(undefined **)(param_2 + 0x48) = &DAT_803dbf8c;
      }
    }
    else {
      *(undefined **)(param_2 + 0x48) = &DAT_803dbf90;
    }
  }
  else {
    iVar4 = FUN_8001ffb4(0x19d);
    if (iVar4 == 0) {
      iVar4 = FUN_8001ffb4(0x1a2);
      if (iVar4 == 0) {
        iVar4 = FUN_8001ffb4(0x102);
        if (iVar4 == 0) {
          iVar4 = FUN_8001ffb4(0x9e);
          if (iVar4 == 0) {
            *(undefined **)(param_2 + 0x48) = &DAT_803dbf94;
          }
          else {
            *(undefined **)(param_2 + 0x48) = &DAT_803dbf98;
          }
        }
        else {
          *(undefined **)(param_2 + 0x48) = &DAT_803dbf9c;
        }
      }
      else {
        *(undefined **)(param_2 + 0x48) = &DAT_803dbfa0;
      }
    }
    else {
      *(undefined **)(param_2 + 0x48) = &DAT_803dbfa4;
    }
  }
  return;
}

