// Function: FUN_80261cc4
// Entry: 80261cc4
// Size: 1040 bytes

int FUN_80261cc4(int param_1)

{
  char cVar1;
  char cVar2;
  char cVar3;
  char cVar4;
  char cVar5;
  char cVar6;
  char cVar7;
  short sVar8;
  byte bVar9;
  int iVar10;
  int iVar11;
  int iVar12;
  undefined *puVar13;
  int iVar14;
  char *pcVar15;
  char *pcVar16;
  byte local_1c [4];
  uint local_18 [2];
  
  iVar12 = param_1 * 0x110;
  if ((&DAT_803af204)[param_1 * 0x44] == 0) {
    iVar10 = FUN_802546e0(param_1,0,local_18);
    if (iVar10 == 0) {
      iVar10 = -3;
    }
    else {
      iVar10 = FUN_80261a7c(local_18[0]);
      if (iVar10 == 0) {
        iVar10 = -2;
      }
      else {
        iVar10 = 0;
      }
    }
    if (-1 < iVar10) {
      *(uint *)(&DAT_803af2e8 + iVar12) = local_18[0];
      *(ushort *)(&DAT_803af1e8 + iVar12) = (ushort)local_18[0] & 0xfc;
      *(undefined4 *)(&DAT_803af1ec + iVar12) =
           *(undefined4 *)(&DAT_8032ed40 + (local_18[0] >> 9 & 0x1c));
      *(short *)(&DAT_803af1f0 + iVar12) =
           (short)(((int)((uint)*(ushort *)(&DAT_803af1e8 + iVar12) << 0x14) >> 3) /
                  *(int *)(&DAT_803af1ec + iVar12));
      *(undefined4 *)(&DAT_803af1f4 + iVar12) =
           *(undefined4 *)(&DAT_8032ed60 + (local_18[0] >> 6 & 0x1c));
      iVar10 = FUN_8025e384(param_1);
      if ((-1 < iVar10) && (iVar10 = FUN_8025e294(param_1,local_1c), -1 < iVar10)) {
        iVar10 = FUN_80253ad4(param_1);
        if (iVar10 == 0) {
          iVar10 = -3;
        }
        else if ((local_1c[0] & 0x40) == 0) {
          iVar10 = FUN_8025f340(param_1,&DAT_803af1f8 + iVar12);
          if (-1 < iVar10) {
            iVar11 = FUN_802451e4();
            puVar13 = (undefined *)(iVar11 + param_1 * 0xc);
            *puVar13 = (&DAT_803af1f8)[iVar12];
            cVar1 = (&DAT_803af1f8)[iVar12];
            puVar13[1] = (&DAT_803af1f9)[iVar12];
            iVar14 = 8;
            cVar2 = (&DAT_803af1f9)[iVar12];
            puVar13[2] = (&DAT_803af1fa)[iVar12];
            cVar3 = (&DAT_803af1fa)[iVar12];
            puVar13[3] = (&DAT_803af1fb)[iVar12];
            cVar4 = (&DAT_803af1fb)[iVar12];
            puVar13[4] = (&DAT_803af1fc)[iVar12];
            cVar5 = (&DAT_803af1fc)[iVar12];
            puVar13[5] = (&DAT_803af1fd)[iVar12];
            cVar6 = (&DAT_803af1fd)[iVar12];
            puVar13[6] = (&DAT_803af1fe)[iVar12];
            cVar7 = (&DAT_803af1fe)[iVar12];
            puVar13[7] = (&DAT_803af1ff)[iVar12];
            bVar9 = cVar1 + cVar2 + cVar3 + cVar4 + cVar5 + cVar6 + cVar7 + (&DAT_803af1ff)[iVar12];
            pcVar15 = puVar13 + 8;
            iVar12 = 4;
            do {
              pcVar16 = (char *)((int)(&DAT_803af1e0 + param_1 * 0x44) + iVar14 + 0x18);
              iVar14 = iVar14 + 1;
              *pcVar15 = *pcVar16;
              pcVar15 = pcVar15 + 1;
              bVar9 = bVar9 + *pcVar16;
              iVar12 = iVar12 + -1;
            } while (iVar12 != 0);
            *(byte *)(iVar11 + param_1 + 0x26) = ~bVar9;
            FUN_8024556c(1);
            return iVar10;
          }
        }
        else {
          (&DAT_803af204)[param_1 * 0x44] = 1;
          iVar11 = FUN_802451e4();
          pcVar15 = (char *)(iVar11 + param_1 * 0xc);
          bVar9 = *pcVar15 + pcVar15[1] + pcVar15[2] + pcVar15[3] + pcVar15[4] + pcVar15[5] +
                  pcVar15[6] + pcVar15[7];
          pcVar15 = pcVar15 + 8;
          iVar10 = 4;
          do {
            cVar1 = *pcVar15;
            pcVar15 = pcVar15 + 1;
            bVar9 = bVar9 + cVar1;
            iVar10 = iVar10 + -1;
          } while (iVar10 != 0);
          FUN_8024556c(0);
          if (*(byte *)(iVar11 + param_1 + 0x26) == (byte)~bVar9) goto LAB_80261fac;
          iVar10 = -5;
        }
      }
    }
LAB_80262088:
    FUN_802545c4(param_1);
    FUN_802623f4(param_1,iVar10);
  }
  else {
LAB_80261fac:
    if ((&DAT_803af204)[param_1 * 0x44] == 1) {
      if (*(undefined1 **)(&DAT_803af2e8 + iVar12) == &DAT_80000004) {
        iVar10 = FUN_802451e4();
        sVar8 = *(short *)(iVar10 + param_1 * 0xc);
        FUN_8024556c(0);
        if ((DAT_803dc608 == -1) || (sVar8 != DAT_803dc608)) {
          iVar10 = -2;
          goto LAB_80262088;
        }
      }
      (&DAT_803af204)[param_1 * 0x44] = 2;
      iVar10 = FUN_8025e1d4(param_1,1);
      if (iVar10 < 0) goto LAB_80262088;
      FUN_802538e4(param_1,&LAB_8025df90);
      FUN_802545c4(param_1);
      FUN_802419b8((&DAT_803af260)[param_1 * 0x44],0xa000);
    }
    iVar10 = FUN_80260308(param_1,*(int *)(&DAT_803af1ec + iVar12) *
                                  ((&DAT_803af204)[param_1 * 0x44] + -2),0x2000,
                          (&DAT_803af260)[param_1 * 0x44] +
                          ((&DAT_803af204)[param_1 * 0x44] + -2) * 0x2000,FUN_802620d4);
    if (iVar10 < 0) {
      FUN_8025ee80(&DAT_803af1e0 + param_1 * 0x44,iVar10);
    }
  }
  return iVar10;
}

