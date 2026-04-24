// Function: FUN_802295a8
// Entry: 802295a8
// Size: 612 bytes

void FUN_802295a8(void)

{
  float fVar1;
  int iVar2;
  int iVar3;
  int iVar4;
  bool bVar5;
  int iVar6;
  int iVar7;
  float *pfVar8;
  int iVar9;
  
  iVar2 = FUN_802860d8();
  pfVar8 = *(float **)(iVar2 + 0xb8);
  iVar7 = *(int *)(iVar2 + 0x4c);
  if ((*(byte *)((int)pfVar8 + 9) & 1) != 0) {
    FUN_802293f8(iVar2,*(undefined *)(pfVar8 + 2));
LAB_802297f4:
    FUN_80286124();
    return;
  }
  *pfVar8 = FLOAT_803db414 * FLOAT_803e6e48 * (pfVar8[1] - *pfVar8) + *pfVar8;
  *(short *)(iVar2 + 4) =
       (short)(int)(FLOAT_803db414 * *pfVar8 +
                   (float)((double)CONCAT44(0x43300000,(int)*(short *)(iVar2 + 4) ^ 0x80000000) -
                          DOUBLE_803e6e50));
  FUN_8000da58(iVar2,0x7f);
  fVar1 = *pfVar8 / *(float *)((int)pfVar8[3] + 8);
  FUN_8000b99c((double)(FLOAT_803e6e68 * fVar1 + FLOAT_803e6e64),iVar2,0x7f,
               (int)(FLOAT_803e6e60 * fVar1 + FLOAT_803e6e5c) & 0xff);
  iVar9 = 0;
  iVar6 = 0;
  do {
    if ((((uint)*(byte *)(pfVar8 + 2) & 1 << iVar9) == 0) &&
       (iVar3 = FUN_8001ffb4((int)*(short *)((int)pfVar8[4] + iVar6)), iVar3 != 0)) {
      bVar5 = false;
      iVar4 = 0;
      iVar3 = iVar9;
      if (0 < iVar9) {
        do {
          if (((uint)*(byte *)(pfVar8 + 2) & 1 << iVar4) == 0) {
            bVar5 = true;
            break;
          }
          iVar4 = iVar4 + 1;
          iVar3 = iVar3 + -1;
        } while (iVar3 != 0);
      }
      if (bVar5) {
        iVar6 = 0;
        iVar9 = 0;
        do {
          FUN_800200e8((int)*(short *)((int)pfVar8[4] + iVar9),0);
          iVar9 = iVar9 + 2;
          iVar6 = iVar6 + 1;
        } while (iVar6 < 3);
        FUN_8000bb18(0,0x487);
        *(undefined *)(pfVar8 + 2) = 0;
        pfVar8[1] = *(float *)pfVar8[3];
LAB_802297b4:
        FUN_802293f8(iVar2,*(undefined *)(pfVar8 + 2));
        if (*(char *)(pfVar8 + 2) == '\a') {
          FUN_800200e8((int)*(short *)(iVar7 + 0x1e),1);
          FUN_8000bb18(0,0x7e);
          *(byte *)((int)pfVar8 + 9) = *(byte *)((int)pfVar8 + 9) | 1;
        }
        goto LAB_802297f4;
      }
      *(byte *)(pfVar8 + 2) = *(byte *)(pfVar8 + 2) | (byte)(1 << iVar9);
      if (iVar9 == 0) {
        pfVar8[1] = *(float *)((int)pfVar8[3] + 4);
        FUN_8000bb18(0,0x409);
      }
      else if (iVar9 == 1) {
        pfVar8[1] = *(float *)((int)pfVar8[3] + 8);
        FUN_8000bb18(0,0x409);
      }
    }
    iVar6 = iVar6 + 2;
    iVar9 = iVar9 + 1;
    if (2 < iVar9) goto LAB_802297b4;
  } while( true );
}

