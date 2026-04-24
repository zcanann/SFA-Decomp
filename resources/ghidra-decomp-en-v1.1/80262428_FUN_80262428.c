// Function: FUN_80262428
// Entry: 80262428
// Size: 1040 bytes

int FUN_80262428(int param_1)

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
  undefined2 *puVar11;
  int iVar12;
  undefined2 *puVar13;
  int iVar14;
  char *pcVar15;
  char *pcVar16;
  byte local_1c [4];
  undefined1 *local_18 [2];
  
  iVar12 = param_1 * 0x110;
  if ((&DAT_803afe64)[param_1 * 0x44] == 0) {
    iVar10 = FUN_80254e44(param_1,0,(byte *)local_18);
    if (iVar10 == 0) {
      iVar10 = -3;
    }
    else {
      iVar10 = FUN_802621e0(local_18[0]);
      if (iVar10 == 0) {
        iVar10 = -2;
      }
      else {
        iVar10 = 0;
      }
    }
    if (-1 < iVar10) {
      *(undefined1 **)(&DAT_803aff48 + iVar12) = local_18[0];
      *(ushort *)(&DAT_803afe48 + iVar12) = (ushort)local_18[0] & 0xfc;
      *(undefined4 *)(&DAT_803afe4c + iVar12) =
           *(undefined4 *)(&DAT_8032f9a0 + ((uint)local_18[0] >> 9 & 0x1c));
      *(short *)(&DAT_803afe50 + iVar12) =
           (short)(((int)((uint)*(ushort *)(&DAT_803afe48 + iVar12) << 0x14) >> 3) /
                  *(int *)(&DAT_803afe4c + iVar12));
      *(undefined4 *)(&DAT_803afe54 + iVar12) =
           *(undefined4 *)(&DAT_8032f9c0 + ((uint)local_18[0] >> 6 & 0x1c));
      iVar10 = FUN_8025eae8(param_1);
      if ((-1 < iVar10) && (iVar10 = FUN_8025e9f8(param_1,local_1c), -1 < iVar10)) {
        iVar10 = FUN_80254238(param_1);
        if (iVar10 == 0) {
          iVar10 = -3;
        }
        else if ((local_1c[0] & 0x40) == 0) {
          iVar10 = FUN_8025faa4(param_1,(uint *)(&DAT_803afe58 + iVar12));
          if (-1 < iVar10) {
            puVar11 = FUN_802458dc();
            puVar13 = puVar11 + param_1 * 6;
            *(undefined *)puVar13 = (&DAT_803afe58)[iVar12];
            cVar1 = (&DAT_803afe58)[iVar12];
            *(undefined *)((int)puVar13 + 1) = (&DAT_803afe59)[iVar12];
            iVar14 = 8;
            cVar2 = (&DAT_803afe59)[iVar12];
            *(undefined *)(puVar13 + 1) = (&DAT_803afe5a)[iVar12];
            cVar3 = (&DAT_803afe5a)[iVar12];
            *(undefined *)((int)puVar13 + 3) = (&DAT_803afe5b)[iVar12];
            cVar4 = (&DAT_803afe5b)[iVar12];
            *(undefined *)(puVar13 + 2) = (&DAT_803afe5c)[iVar12];
            cVar5 = (&DAT_803afe5c)[iVar12];
            *(undefined *)((int)puVar13 + 5) = (&DAT_803afe5d)[iVar12];
            cVar6 = (&DAT_803afe5d)[iVar12];
            *(undefined *)(puVar13 + 3) = (&DAT_803afe5e)[iVar12];
            cVar7 = (&DAT_803afe5e)[iVar12];
            *(undefined *)((int)puVar13 + 7) = (&DAT_803afe5f)[iVar12];
            bVar9 = cVar1 + cVar2 + cVar3 + cVar4 + cVar5 + cVar6 + cVar7 + (&DAT_803afe5f)[iVar12];
            pcVar15 = (char *)(puVar13 + 4);
            iVar12 = 4;
            do {
              pcVar16 = (char *)((int)(&DAT_803afe40 + param_1 * 0x44) + iVar14 + 0x18);
              iVar14 = iVar14 + 1;
              *pcVar15 = *pcVar16;
              pcVar15 = pcVar15 + 1;
              bVar9 = bVar9 + *pcVar16;
              iVar12 = iVar12 + -1;
            } while (iVar12 != 0);
            *(byte *)((int)puVar11 + param_1 + 0x26) = ~bVar9;
            FUN_80245c64(1);
            return iVar10;
          }
        }
        else {
          (&DAT_803afe64)[param_1 * 0x44] = 1;
          puVar11 = FUN_802458dc();
          pcVar15 = (char *)(puVar11 + param_1 * 6);
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
          FUN_80245c64(0);
          if (*(byte *)((int)puVar11 + param_1 + 0x26) == (byte)~bVar9) goto LAB_80262710;
          iVar10 = -5;
        }
      }
    }
LAB_802627ec:
    FUN_80254d28(param_1);
    FUN_80262b58(param_1,iVar10);
  }
  else {
LAB_80262710:
    if ((&DAT_803afe64)[param_1 * 0x44] == 1) {
      if (*(undefined1 **)(&DAT_803aff48 + iVar12) == &DAT_80000004) {
        puVar11 = FUN_802458dc();
        sVar8 = puVar11[param_1 * 6];
        FUN_80245c64(0);
        if ((DAT_803dd270 == -1) || (sVar8 != DAT_803dd270)) {
          iVar10 = -2;
          goto LAB_802627ec;
        }
      }
      (&DAT_803afe64)[param_1 * 0x44] = 2;
      iVar10 = FUN_8025e938(param_1,1);
      if (iVar10 < 0) goto LAB_802627ec;
      FUN_80254048(param_1,-0x7fda190c);
      FUN_80254d28(param_1);
      FUN_802420b0((&DAT_803afec0)[param_1 * 0x44],0xa000);
    }
    iVar10 = FUN_80260a6c(param_1,*(int *)(&DAT_803afe4c + iVar12) *
                                  ((&DAT_803afe64)[param_1 * 0x44] + -2),0x2000,
                          (&DAT_803afec0)[param_1 * 0x44] +
                          ((&DAT_803afe64)[param_1 * 0x44] + -2) * 0x2000,FUN_80262838);
    if (iVar10 < 0) {
      FUN_8025f5e4(&DAT_803afe40 + param_1 * 0x44,iVar10);
    }
  }
  return iVar10;
}

