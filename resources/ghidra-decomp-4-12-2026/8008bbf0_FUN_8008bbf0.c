// Function: FUN_8008bbf0
// Entry: 8008bbf0
// Size: 608 bytes

void FUN_8008bbf0(void)

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
  
  local_18[0] = FLOAT_803dfcd8;
  puVar5 = FUN_800e877c();
  if ((DAT_803dddac != 0) && (DAT_803dddd4 != 0)) {
    *(float *)(DAT_803dddac + 0x20c) =
         *(float *)(DAT_803dddac + 0x214) * FLOAT_803dc074 + *(float *)(DAT_803dddac + 0x20c);
    fVar1 = *(float *)(DAT_803dddac + 0x20c);
    if (fVar1 < FLOAT_803dfcf8) {
      if (fVar1 < FLOAT_803dfcd8) {
        *(float *)(DAT_803dddac + 0x20c) = fVar1 + FLOAT_803dfcf8;
      }
    }
    else {
      *(float *)(DAT_803dddac + 0x20c) = fVar1 - FLOAT_803dfcf8;
    }
    iVar6 = FUN_8008ba7c(local_18);
    if (iVar6 == 0) {
      if (*(char *)(DAT_803dddac + 0x24e) != '\0') {
        iVar6 = *(int *)(DAT_803dddac + 0x218) + 1;
        *(int *)(DAT_803dddac + 0x218) = iVar6;
        if (0x1e < iVar6) {
          *(undefined4 *)(DAT_803dddac + 0x218) = 0;
        }
        *(undefined *)(DAT_803dddac + 0x24e) = 0;
      }
    }
    else if (*(char *)(DAT_803dddac + 0x24e) == '\0') {
      *(undefined *)(DAT_803dddac + 0x24e) = 1;
    }
    iVar6 = FUN_8002bac4();
    if (iVar6 != 0) {
      *puVar5 = *(undefined4 *)(DAT_803dddac + 0x20c);
    }
    fVar4 = FLOAT_803dfd70;
    fVar1 = FLOAT_803dfcd8;
    iVar6 = 0;
    iVar8 = 2;
    do {
      iVar7 = DAT_803dddac + iVar6;
      *(float *)(iVar7 + 0xb8) =
           -(*(float *)(iVar7 + 0xb4) * FLOAT_803dc074 - *(float *)(iVar7 + 0xb8));
      fVar2 = *(float *)(DAT_803dddac + iVar6 + 0xb8);
      fVar3 = fVar1;
      if ((fVar1 <= fVar2) && (fVar3 = fVar2, FLOAT_803dfcdc < fVar2)) {
        fVar3 = FLOAT_803dfcdc;
      }
      *(float *)(DAT_803dddac + iVar6 + 0xb8) = fVar3;
      iVar7 = iVar6 + 0xbc;
      *(float *)(DAT_803dddac + iVar7) =
           -(fVar4 * FLOAT_803dc074 - *(float *)(DAT_803dddac + iVar7));
      fVar2 = *(float *)(DAT_803dddac + iVar7);
      fVar3 = fVar1;
      if ((fVar1 <= fVar2) && (fVar3 = fVar2, FLOAT_803dfcdc < fVar2)) {
        fVar3 = FLOAT_803dfcdc;
      }
      *(float *)(DAT_803dddac + iVar7) = fVar3;
      iVar6 = iVar6 + 0xa4;
      iVar8 = iVar8 + -1;
    } while (iVar8 != 0);
    *(float *)(DAT_803dddac + 0x23c) =
         -(*(float *)(DAT_803dddac + 0x240) * FLOAT_803dc074 - *(float *)(DAT_803dddac + 0x23c));
    fVar1 = *(float *)(DAT_803dddac + 0x23c);
    fVar4 = FLOAT_803dfcd8;
    if ((FLOAT_803dfcd8 <= fVar1) && (fVar4 = fVar1, FLOAT_803dfcdc < fVar1)) {
      fVar4 = FLOAT_803dfcdc;
    }
    *(float *)(DAT_803dddac + 0x23c) = fVar4;
    *(float *)(DAT_803dddac + 0x244) =
         *(float *)(DAT_803dddac + 0x248) * FLOAT_803dc074 + *(float *)(DAT_803dddac + 0x244);
    fVar1 = *(float *)(DAT_803dddac + 0x244);
    fVar4 = FLOAT_803dfcd8;
    if ((FLOAT_803dfcd8 <= fVar1) && (fVar4 = fVar1, FLOAT_803dfcdc < fVar1)) {
      fVar4 = FLOAT_803dfcdc;
    }
    *(float *)(DAT_803dddac + 0x244) = fVar4;
  }
  return;
}

