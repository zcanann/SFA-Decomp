// Function: FUN_80229c6c
// Entry: 80229c6c
// Size: 612 bytes

void FUN_80229c6c(void)

{
  float fVar1;
  bool bVar2;
  uint uVar3;
  int iVar4;
  int iVar5;
  int iVar6;
  float *pfVar7;
  int iVar8;
  int iVar9;
  
  uVar3 = FUN_8028683c();
  pfVar7 = *(float **)(uVar3 + 0xb8);
  iVar6 = *(int *)(uVar3 + 0x4c);
  if ((*(byte *)((int)pfVar7 + 9) & 1) != 0) {
    FUN_80229abc();
LAB_80229eb8:
    FUN_80286888();
    return;
  }
  *pfVar7 = FLOAT_803dc074 * FLOAT_803e7ae0 * (pfVar7[1] - *pfVar7) + *pfVar7;
  *(short *)(uVar3 + 4) =
       (short)(int)(FLOAT_803dc074 * *pfVar7 +
                   (float)((double)CONCAT44(0x43300000,(int)*(short *)(uVar3 + 4) ^ 0x80000000) -
                          DOUBLE_803e7ae8));
  FUN_8000da78(uVar3,0x7f);
  fVar1 = *pfVar7 / *(float *)((int)pfVar7[3] + 8);
  FUN_8000b9bc((double)(FLOAT_803e7b00 * fVar1 + FLOAT_803e7afc),uVar3,0x7f,
               (byte)(int)(FLOAT_803e7af8 * fVar1 + FLOAT_803e7af4));
  iVar8 = 0;
  iVar5 = 0;
  do {
    if ((((uint)*(byte *)(pfVar7 + 2) & 1 << iVar8) == 0) &&
       (uVar3 = FUN_80020078((int)*(short *)((int)pfVar7[4] + iVar5)), uVar3 != 0)) {
      bVar2 = false;
      iVar4 = 0;
      iVar9 = iVar8;
      if (0 < iVar8) {
        do {
          if (((uint)*(byte *)(pfVar7 + 2) & 1 << iVar4) == 0) {
            bVar2 = true;
            break;
          }
          iVar4 = iVar4 + 1;
          iVar9 = iVar9 + -1;
        } while (iVar9 != 0);
      }
      if (bVar2) {
        iVar5 = 0;
        iVar8 = 0;
        do {
          FUN_800201ac((int)*(short *)((int)pfVar7[4] + iVar8),0);
          iVar8 = iVar8 + 2;
          iVar5 = iVar5 + 1;
        } while (iVar5 < 3);
        FUN_8000bb38(0,0x487);
        *(undefined *)(pfVar7 + 2) = 0;
        pfVar7[1] = *(float *)pfVar7[3];
LAB_80229e78:
        FUN_80229abc();
        if (*(char *)(pfVar7 + 2) == '\a') {
          FUN_800201ac((int)*(short *)(iVar6 + 0x1e),1);
          FUN_8000bb38(0,0x7e);
          *(byte *)((int)pfVar7 + 9) = *(byte *)((int)pfVar7 + 9) | 1;
        }
        goto LAB_80229eb8;
      }
      *(byte *)(pfVar7 + 2) = *(byte *)(pfVar7 + 2) | (byte)(1 << iVar8);
      if (iVar8 == 0) {
        pfVar7[1] = *(float *)((int)pfVar7[3] + 4);
        FUN_8000bb38(0,0x409);
      }
      else if (iVar8 == 1) {
        pfVar7[1] = *(float *)((int)pfVar7[3] + 8);
        FUN_8000bb38(0,0x409);
      }
    }
    iVar5 = iVar5 + 2;
    iVar8 = iVar8 + 1;
    if (2 < iVar8) goto LAB_80229e78;
  } while( true );
}

