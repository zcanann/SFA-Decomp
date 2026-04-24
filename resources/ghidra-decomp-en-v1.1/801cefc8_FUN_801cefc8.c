// Function: FUN_801cefc8
// Entry: 801cefc8
// Size: 788 bytes

void FUN_801cefc8(short *param_1,int param_2,int param_3)

{
  byte bVar1;
  float fVar2;
  float fVar3;
  int iVar4;
  uint uVar5;
  double dVar6;
  
  iVar4 = FUN_801ce62c((uint)param_1,param_2);
  if (iVar4 == 0) {
    if (((*(byte *)((int)param_1 + 0xaf) & 4) != 0) || (*(float *)(param_2 + 0x18) < FLOAT_803e5edc)
       ) {
      *(float *)(param_2 + 0x54) = -(FLOAT_803e5ee0 * FLOAT_803dc074 - *(float *)(param_2 + 0x54));
      if (*(float *)(param_2 + 0x54) < FLOAT_803e5ed8) {
        *(float *)(param_2 + 0x54) = FLOAT_803e5ea4;
      }
    }
    else {
      *(float *)(param_2 + 0x54) = FLOAT_803e5ed4 * FLOAT_803dc074 + *(float *)(param_2 + 0x54);
      if (FLOAT_803e5ee4 < *(float *)(param_2 + 0x54)) {
        *(float *)(param_2 + 0x54) = FLOAT_803e5ee4;
      }
    }
  }
  else if (iVar4 < 0) {
    if ((-2 < iVar4) &&
       (*(float *)(param_2 + 0x54) = -(FLOAT_803e5ed4 * FLOAT_803dc074 - *(float *)(param_2 + 0x54))
       , *(float *)(param_2 + 0x54) < FLOAT_803e5ed8)) {
      *(float *)(param_2 + 0x54) = FLOAT_803e5ea4;
    }
  }
  else if (iVar4 < 2) {
    return;
  }
  bVar1 = *(byte *)(param_2 + 0x408);
  if (bVar1 == 8) {
    iVar4 = FUN_80010340((double)*(float *)(param_2 + 0x54),(float *)(param_2 + 0x5c));
    if ((iVar4 != 0) || (*(int *)(param_2 + 0x6c) != 0)) {
      (**(code **)(*DAT_803dd71c + 0x90))((float *)(param_2 + 0x5c));
    }
    fVar2 = *(float *)(param_2 + 0xc4) - *(float *)(param_1 + 6);
    fVar3 = *(float *)(param_2 + 0xcc) - *(float *)(param_1 + 10);
    dVar6 = FUN_80293900((double)(fVar2 * fVar2 + fVar3 * fVar3));
    FUN_8002f6cc((double)(float)((double)FLOAT_803dc078 * dVar6),(int)param_1,
                 (float *)(param_2 + 0x4c));
    iVar4 = FUN_80021884();
    *param_1 = (short)iVar4 + -0x8000;
    *(undefined4 *)(param_1 + 6) = *(undefined4 *)(param_2 + 0xc4);
    *(undefined4 *)(param_1 + 10) = *(undefined4 *)(param_2 + 0xcc);
    if (*(float *)(param_2 + 0x54) <= FLOAT_803e5ea4) {
      *(undefined *)(param_2 + 0x408) = 7;
    }
  }
  else if (((bVar1 < 8) && (6 < bVar1)) && (FLOAT_803e5ee8 < *(float *)(param_2 + 0x54))) {
    *(undefined *)(param_2 + 0x408) = 8;
  }
  if (*(char *)(param_3 + 0x1d) == '\x01') {
    uVar5 = FUN_80020078(0x19d);
    if (uVar5 == 0) {
      uVar5 = FUN_80020078(0x1a2);
      if (uVar5 == 0) {
        uVar5 = FUN_80020078(0x102);
        if (uVar5 == 0) {
          uVar5 = FUN_80020078(0x9e);
          if (uVar5 == 0) {
            *(undefined **)(param_2 + 0x48) = &DAT_803dcbe8;
          }
          else {
            *(undefined **)(param_2 + 0x48) = &DAT_803dcbec;
          }
        }
        else {
          *(undefined **)(param_2 + 0x48) = &DAT_803dcbf0;
        }
      }
      else {
        *(undefined **)(param_2 + 0x48) = &DAT_803dcbf4;
      }
    }
    else {
      *(undefined **)(param_2 + 0x48) = &DAT_803dcbf8;
    }
  }
  else {
    uVar5 = FUN_80020078(0x19d);
    if (uVar5 == 0) {
      uVar5 = FUN_80020078(0x1a2);
      if (uVar5 == 0) {
        uVar5 = FUN_80020078(0x102);
        if (uVar5 == 0) {
          uVar5 = FUN_80020078(0x9e);
          if (uVar5 == 0) {
            *(undefined **)(param_2 + 0x48) = &DAT_803dcbfc;
          }
          else {
            *(undefined **)(param_2 + 0x48) = &DAT_803dcc00;
          }
        }
        else {
          *(undefined **)(param_2 + 0x48) = &DAT_803dcc04;
        }
      }
      else {
        *(undefined **)(param_2 + 0x48) = &DAT_803dcc08;
      }
    }
    else {
      *(undefined **)(param_2 + 0x48) = &DAT_803dcc0c;
    }
  }
  return;
}

