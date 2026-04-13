// Function: FUN_801fc100
// Entry: 801fc100
// Size: 668 bytes

/* WARNING: Removing unreachable block (ram,0x801fc160) */

void FUN_801fc100(int param_1)

{
  byte bVar1;
  float fVar2;
  uint uVar3;
  int iVar4;
  short *psVar5;
  
  iVar4 = *(int *)(param_1 + 0x4c);
  psVar5 = *(short **)(param_1 + 0xb8);
  uVar3 = FUN_80020078((int)*psVar5);
  if (uVar3 != 0) {
    *(undefined *)(psVar5 + 1) = 6;
  }
  fVar2 = FLOAT_803e6da0;
  bVar1 = *(byte *)(psVar5 + 1);
  if (bVar1 == 3) {
    if (*(float *)(iVar4 + 0x10) - FLOAT_803e6da0 < *(float *)(param_1 + 0x14)) {
      *(float *)(param_1 + 0x14) = *(float *)(param_1 + 0x14) - FLOAT_803dc074;
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
          if (*(float *)(param_1 + 0x14) == *(float *)(iVar4 + 0x10) - FLOAT_803e6da0) {
            *(undefined *)(psVar5 + 1) = 2;
          }
          if (*(float *)(param_1 + 0x14) == FLOAT_803e6da0 + *(float *)(iVar4 + 0x10)) {
            *(undefined *)(psVar5 + 1) = 3;
          }
        }
        else {
          if (*(float *)(param_1 + 0x14) == *(float *)(iVar4 + 0x10) - FLOAT_803e6da0) {
            *(undefined *)(psVar5 + 1) = 4;
          }
          if (*(float *)(param_1 + 0x14) == FLOAT_803e6da0 + *(float *)(iVar4 + 0x10)) {
            *(undefined *)(psVar5 + 1) = 5;
          }
        }
      }
      else {
        psVar5[2] = psVar5[2] - (short)(int)FLOAT_803dc074;
        if (psVar5[2] < 1) {
          psVar5[2] = 0;
        }
      }
    }
    else if (bVar1 == 0) {
      uVar3 = FUN_80020078((int)*psVar5);
      if (uVar3 == 0) {
        *(undefined *)(psVar5 + 1) = 3;
      }
    }
    else if (*(float *)(param_1 + 0x14) < FLOAT_803e6da0 + *(float *)(iVar4 + 0x10)) {
      *(float *)(param_1 + 0x14) = *(float *)(param_1 + 0x14) + FLOAT_803dc074;
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
        uVar3 = FUN_80020078((int)*psVar5);
        if (uVar3 == 0) {
          *(undefined *)(psVar5 + 1) = 3;
        }
      }
      else {
        *(float *)(param_1 + 0x14) = fVar2 - FLOAT_803dc074;
        if (*(float *)(param_1 + 0x14) <= *(float *)(iVar4 + 0x10)) {
          *(float *)(param_1 + 0x14) = *(float *)(iVar4 + 0x10);
        }
      }
    }
    else {
      *(float *)(param_1 + 0x14) = fVar2 + FLOAT_803dc074;
      if (*(float *)(iVar4 + 0x10) <= *(float *)(param_1 + 0x14)) {
        *(float *)(param_1 + 0x14) = *(float *)(iVar4 + 0x10);
      }
    }
  }
  return;
}

