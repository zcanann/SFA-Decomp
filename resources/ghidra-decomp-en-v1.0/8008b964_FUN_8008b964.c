// Function: FUN_8008b964
// Entry: 8008b964
// Size: 608 bytes

void FUN_8008b964(void)

{
  float fVar1;
  float fVar2;
  float fVar3;
  float fVar4;
  undefined4 *puVar5;
  int iVar6;
  int iVar7;
  int iVar8;
  float local_18 [5];
  
  local_18[0] = FLOAT_803df058;
  puVar5 = (undefined4 *)FUN_800e84f8();
  if ((DAT_803dd12c != 0) && (DAT_803dd154 != 0)) {
    *(float *)(DAT_803dd12c + 0x20c) =
         *(float *)(DAT_803dd12c + 0x214) * FLOAT_803db414 + *(float *)(DAT_803dd12c + 0x20c);
    fVar1 = *(float *)(DAT_803dd12c + 0x20c);
    if (fVar1 < FLOAT_803df078) {
      if (fVar1 < FLOAT_803df058) {
        *(float *)(DAT_803dd12c + 0x20c) = fVar1 + FLOAT_803df078;
      }
    }
    else {
      *(float *)(DAT_803dd12c + 0x20c) = fVar1 - FLOAT_803df078;
    }
    iVar6 = FUN_8008b7f0(local_18);
    if (iVar6 == 0) {
      if (*(char *)(DAT_803dd12c + 0x24e) != '\0') {
        iVar6 = *(int *)(DAT_803dd12c + 0x218) + 1;
        *(int *)(DAT_803dd12c + 0x218) = iVar6;
        if (0x1e < iVar6) {
          *(undefined4 *)(DAT_803dd12c + 0x218) = 0;
        }
        *(undefined *)(DAT_803dd12c + 0x24e) = 0;
      }
    }
    else if (*(char *)(DAT_803dd12c + 0x24e) == '\0') {
      *(undefined *)(DAT_803dd12c + 0x24e) = 1;
    }
    iVar6 = FUN_8002b9ec();
    if (iVar6 != 0) {
      *puVar5 = *(undefined4 *)(DAT_803dd12c + 0x20c);
    }
    fVar4 = FLOAT_803df0f0;
    fVar1 = FLOAT_803df058;
    iVar6 = 0;
    iVar8 = 2;
    do {
      iVar7 = DAT_803dd12c + iVar6;
      *(float *)(iVar7 + 0xb8) =
           -(*(float *)(iVar7 + 0xb4) * FLOAT_803db414 - *(float *)(iVar7 + 0xb8));
      fVar2 = *(float *)(DAT_803dd12c + iVar6 + 0xb8);
      fVar3 = fVar1;
      if ((fVar1 <= fVar2) && (fVar3 = fVar2, FLOAT_803df05c < fVar2)) {
        fVar3 = FLOAT_803df05c;
      }
      *(float *)(DAT_803dd12c + iVar6 + 0xb8) = fVar3;
      iVar7 = iVar6 + 0xbc;
      *(float *)(DAT_803dd12c + iVar7) =
           -(fVar4 * FLOAT_803db414 - *(float *)(DAT_803dd12c + iVar7));
      fVar2 = *(float *)(DAT_803dd12c + iVar7);
      fVar3 = fVar1;
      if ((fVar1 <= fVar2) && (fVar3 = fVar2, FLOAT_803df05c < fVar2)) {
        fVar3 = FLOAT_803df05c;
      }
      *(float *)(DAT_803dd12c + iVar7) = fVar3;
      iVar6 = iVar6 + 0xa4;
      iVar8 = iVar8 + -1;
    } while (iVar8 != 0);
    *(float *)(DAT_803dd12c + 0x23c) =
         -(*(float *)(DAT_803dd12c + 0x240) * FLOAT_803db414 - *(float *)(DAT_803dd12c + 0x23c));
    fVar1 = *(float *)(DAT_803dd12c + 0x23c);
    fVar4 = FLOAT_803df058;
    if ((FLOAT_803df058 <= fVar1) && (fVar4 = fVar1, FLOAT_803df05c < fVar1)) {
      fVar4 = FLOAT_803df05c;
    }
    *(float *)(DAT_803dd12c + 0x23c) = fVar4;
    *(float *)(DAT_803dd12c + 0x244) =
         *(float *)(DAT_803dd12c + 0x248) * FLOAT_803db414 + *(float *)(DAT_803dd12c + 0x244);
    fVar1 = *(float *)(DAT_803dd12c + 0x244);
    fVar4 = FLOAT_803df058;
    if ((FLOAT_803df058 <= fVar1) && (fVar4 = fVar1, FLOAT_803df05c < fVar1)) {
      fVar4 = FLOAT_803df05c;
    }
    *(float *)(DAT_803dd12c + 0x244) = fVar4;
  }
  return;
}

