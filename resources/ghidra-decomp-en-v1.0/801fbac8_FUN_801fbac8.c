// Function: FUN_801fbac8
// Entry: 801fbac8
// Size: 668 bytes

/* WARNING: Removing unreachable block (ram,0x801fbb28) */

void FUN_801fbac8(int param_1)

{
  byte bVar1;
  float fVar2;
  int iVar3;
  int iVar4;
  short *psVar5;
  
  iVar4 = *(int *)(param_1 + 0x4c);
  psVar5 = *(short **)(param_1 + 0xb8);
  iVar3 = FUN_8001ffb4((int)*psVar5);
  if (iVar3 != 0) {
    *(undefined *)(psVar5 + 1) = 6;
  }
  fVar2 = FLOAT_803e6108;
  bVar1 = *(byte *)(psVar5 + 1);
  if (bVar1 == 3) {
    if (*(float *)(iVar4 + 0x10) - FLOAT_803e6108 < *(float *)(param_1 + 0x14)) {
      *(float *)(param_1 + 0x14) = *(float *)(param_1 + 0x14) - FLOAT_803db414;
      fVar2 = *(float *)(iVar4 + 0x10) - fVar2;
      if (*(float *)(param_1 + 0x14) <= fVar2) {
        *(float *)(param_1 + 0x14) = fVar2;
        *(undefined *)(psVar5 + 1) = 1;
        psVar5[2] = 0x14;
      }
    }
  }
  else if (bVar1 < 3) {
    if (bVar1 == 1) {
      if (psVar5[2] == 0) {
        if (*(char *)((int)psVar5 + 3) == '\0') {
          if (*(float *)(param_1 + 0x14) == *(float *)(iVar4 + 0x10) - FLOAT_803e6108) {
            *(undefined *)(psVar5 + 1) = 2;
          }
          if (*(float *)(param_1 + 0x14) == FLOAT_803e6108 + *(float *)(iVar4 + 0x10)) {
            *(undefined *)(psVar5 + 1) = 3;
          }
        }
        else {
          if (*(float *)(param_1 + 0x14) == *(float *)(iVar4 + 0x10) - FLOAT_803e6108) {
            *(undefined *)(psVar5 + 1) = 4;
          }
          if (*(float *)(param_1 + 0x14) == FLOAT_803e6108 + *(float *)(iVar4 + 0x10)) {
            *(undefined *)(psVar5 + 1) = 5;
          }
        }
      }
      else {
        psVar5[2] = psVar5[2] - (short)(int)FLOAT_803db414;
        if (psVar5[2] < 1) {
          psVar5[2] = 0;
        }
      }
    }
    else if (bVar1 == 0) {
      iVar3 = FUN_8001ffb4((int)*psVar5);
      if (iVar3 == 0) {
        *(undefined *)(psVar5 + 1) = 3;
      }
    }
    else if (*(float *)(param_1 + 0x14) < FLOAT_803e6108 + *(float *)(iVar4 + 0x10)) {
      *(float *)(param_1 + 0x14) = *(float *)(param_1 + 0x14) + FLOAT_803db414;
      fVar2 = fVar2 + *(float *)(iVar4 + 0x10);
      if (fVar2 <= *(float *)(param_1 + 0x14)) {
        *(float *)(param_1 + 0x14) = fVar2;
        *(undefined *)(psVar5 + 1) = 1;
        psVar5[2] = 0x14;
      }
    }
  }
  else if (bVar1 == 6) {
    fVar2 = *(float *)(param_1 + 0x14);
    if (*(float *)(iVar4 + 0x10) <= fVar2) {
      if (fVar2 <= *(float *)(iVar4 + 0x10)) {
        iVar3 = FUN_8001ffb4((int)*psVar5);
        if (iVar3 == 0) {
          *(undefined *)(psVar5 + 1) = 3;
        }
      }
      else {
        *(float *)(param_1 + 0x14) = fVar2 - FLOAT_803db414;
        if (*(float *)(param_1 + 0x14) <= *(float *)(iVar4 + 0x10)) {
          *(float *)(param_1 + 0x14) = *(float *)(iVar4 + 0x10);
        }
      }
    }
    else {
      *(float *)(param_1 + 0x14) = fVar2 + FLOAT_803db414;
      if (*(float *)(iVar4 + 0x10) <= *(float *)(param_1 + 0x14)) {
        *(float *)(param_1 + 0x14) = *(float *)(iVar4 + 0x10);
      }
    }
  }
  return;
}

