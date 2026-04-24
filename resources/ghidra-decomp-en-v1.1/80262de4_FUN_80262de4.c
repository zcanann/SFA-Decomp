// Function: FUN_80262de4
// Entry: 80262de4
// Size: 1624 bytes

int FUN_80262de4(int param_1,ushort param_2,undefined *param_3)

{
  ulonglong uVar1;
  uint uVar2;
  int iVar3;
  undefined2 *puVar4;
  uint uVar5;
  ushort uVar6;
  short *psVar7;
  char *pcVar8;
  ushort *puVar9;
  short sVar10;
  char *pcVar11;
  ulonglong uVar12;
  longlong lVar13;
  undefined8 uVar14;
  int *local_40 [2];
  
  iVar3 = FUN_8025f52c(param_1,local_40);
  if (-1 < iVar3) {
    puVar9 = (ushort *)local_40[0][0x20];
    FUN_800033a8((int)puVar9,0xff,0x2000);
    uVar6 = DAT_cc00206e;
    puVar9[0x12] = param_2;
    puVar4 = FUN_80245880();
    *(undefined4 *)(puVar9 + 10) = *(undefined4 *)(puVar4 + 6);
    *(uint *)(puVar9 + 0xc) = (uint)*(byte *)(puVar4 + 9);
    FUN_80245c40(0);
    uVar12 = FUN_802473b4();
    puVar4 = FUN_802458dc();
    pcVar11 = (char *)(puVar4 + param_1 * 6);
    sVar10 = 0;
    pcVar8 = pcVar11;
    uVar1 = uVar12;
    while( true ) {
      if (3 < sVar10) break;
      uVar2 = (int)uVar1 * 0x41c64e6d;
      lVar13 = FUN_80286bf4((int)(uVar1 >> 0x20) * 0x41c64e6d +
                            (int)((uVar1 & 0xffffffff) * 0x41c64e6d >> 0x20) +
                            (uint)(0xffffcfc6 < uVar2),uVar2 + 0x3039,0x10);
      *(char *)((int)puVar9 + (int)sVar10) = (char)lVar13 + *pcVar8;
      lVar13 = lVar13 * 0x41c64e6d + 0x3039;
      uVar14 = FUN_80286bf4((int)((ulonglong)lVar13 >> 0x20),(uint)lVar13,0x10);
      uVar5 = (uint)uVar14 & 0x7fff;
      uVar2 = uVar5 * 0x41c64e6d;
      lVar13 = FUN_80286bf4((int)((ulonglong)uVar5 * 0x41c64e6d >> 0x20) +
                            (uint)(0xffffcfc6 < uVar2),uVar2 + 0x3039,0x10);
      *(char *)((int)puVar9 + (int)(short)(sVar10 + 1)) =
           (char)lVar13 + pcVar11[(short)(sVar10 + 1)];
      lVar13 = lVar13 * 0x41c64e6d + 0x3039;
      uVar14 = FUN_80286bf4((int)((ulonglong)lVar13 >> 0x20),(uint)lVar13,0x10);
      uVar5 = (uint)uVar14 & 0x7fff;
      uVar2 = uVar5 * 0x41c64e6d;
      lVar13 = FUN_80286bf4((int)((ulonglong)uVar5 * 0x41c64e6d >> 0x20) +
                            (uint)(0xffffcfc6 < uVar2),uVar2 + 0x3039,0x10);
      *(char *)((int)puVar9 + (int)(short)(sVar10 + 2)) =
           (char)lVar13 + pcVar11[(short)(sVar10 + 2)];
      lVar13 = lVar13 * 0x41c64e6d + 0x3039;
      uVar14 = FUN_80286bf4((int)((ulonglong)lVar13 >> 0x20),(uint)lVar13,0x10);
      uVar5 = (uint)uVar14 & 0x7fff;
      uVar2 = uVar5 * 0x41c64e6d;
      lVar13 = FUN_80286bf4((int)((ulonglong)uVar5 * 0x41c64e6d >> 0x20) +
                            (uint)(0xffffcfc6 < uVar2),uVar2 + 0x3039,0x10);
      *(char *)((int)puVar9 + (int)(short)(sVar10 + 3)) =
           (char)lVar13 + pcVar11[(short)(sVar10 + 3)];
      lVar13 = lVar13 * 0x41c64e6d + 0x3039;
      uVar14 = FUN_80286bf4((int)((ulonglong)lVar13 >> 0x20),(uint)lVar13,0x10);
      uVar5 = (uint)uVar14 & 0x7fff;
      uVar2 = uVar5 * 0x41c64e6d;
      lVar13 = FUN_80286bf4((int)((ulonglong)uVar5 * 0x41c64e6d >> 0x20) +
                            (uint)(0xffffcfc6 < uVar2),uVar2 + 0x3039,0x10);
      *(char *)((int)puVar9 + (int)(short)(sVar10 + 4)) =
           (char)lVar13 + pcVar11[(short)(sVar10 + 4)];
      lVar13 = lVar13 * 0x41c64e6d + 0x3039;
      uVar14 = FUN_80286bf4((int)((ulonglong)lVar13 >> 0x20),(uint)lVar13,0x10);
      uVar5 = (uint)uVar14 & 0x7fff;
      uVar2 = uVar5 * 0x41c64e6d;
      lVar13 = FUN_80286bf4((int)((ulonglong)uVar5 * 0x41c64e6d >> 0x20) +
                            (uint)(0xffffcfc6 < uVar2),uVar2 + 0x3039,0x10);
      *(char *)((int)puVar9 + (int)(short)(sVar10 + 5)) =
           (char)lVar13 + pcVar11[(short)(sVar10 + 5)];
      lVar13 = lVar13 * 0x41c64e6d + 0x3039;
      uVar14 = FUN_80286bf4((int)((ulonglong)lVar13 >> 0x20),(uint)lVar13,0x10);
      uVar5 = (uint)uVar14 & 0x7fff;
      uVar2 = uVar5 * 0x41c64e6d;
      lVar13 = FUN_80286bf4((int)((ulonglong)uVar5 * 0x41c64e6d >> 0x20) +
                            (uint)(0xffffcfc6 < uVar2),uVar2 + 0x3039,0x10);
      *(char *)((int)puVar9 + (int)(short)(sVar10 + 6)) =
           (char)lVar13 + pcVar11[(short)(sVar10 + 6)];
      lVar13 = lVar13 * 0x41c64e6d + 0x3039;
      uVar14 = FUN_80286bf4((int)((ulonglong)lVar13 >> 0x20),(uint)lVar13,0x10);
      uVar5 = (uint)uVar14 & 0x7fff;
      uVar2 = uVar5 * 0x41c64e6d;
      lVar13 = FUN_80286bf4((int)((ulonglong)uVar5 * 0x41c64e6d >> 0x20) +
                            (uint)(0xffffcfc6 < uVar2),uVar2 + 0x3039,0x10);
      *(char *)((int)puVar9 + (int)(short)(sVar10 + 7)) =
           (char)lVar13 + pcVar11[(short)(sVar10 + 7)];
      lVar13 = lVar13 * 0x41c64e6d + 0x3039;
      uVar14 = FUN_80286bf4((int)((ulonglong)lVar13 >> 0x20),(uint)lVar13,0x10);
      uVar1 = (ulonglong)((uint)uVar14 & 0x7fff);
      pcVar8 = pcVar8 + 8;
      sVar10 = sVar10 + 8;
    }
    pcVar11 = pcVar11 + sVar10;
    while( true ) {
      if (0xb < sVar10) break;
      uVar2 = (int)uVar1 * 0x41c64e6d;
      lVar13 = FUN_80286bf4((int)(uVar1 >> 0x20) * 0x41c64e6d +
                            (int)((uVar1 & 0xffffffff) * 0x41c64e6d >> 0x20) +
                            (uint)(0xffffcfc6 < uVar2),uVar2 + 0x3039,0x10);
      *(char *)((int)puVar9 + (int)sVar10) = (char)lVar13 + *pcVar11;
      lVar13 = lVar13 * 0x41c64e6d + 0x3039;
      uVar14 = FUN_80286bf4((int)((ulonglong)lVar13 >> 0x20),(uint)lVar13,0x10);
      uVar1 = (ulonglong)((uint)uVar14 & 0x7fff);
      pcVar11 = pcVar11 + 1;
      sVar10 = sVar10 + 1;
    }
    FUN_80245c64(0);
    *(uint *)(puVar9 + 0xe) = (uint)uVar6;
    *(ulonglong *)(puVar9 + 6) = uVar12;
    puVar9[0x10] = 0;
    puVar9[0x11] = *(ushort *)(local_40[0] + 2);
    FUN_80261278(puVar9,0x1fc,(short *)(puVar9 + 0xfe),(short *)(puVar9 + 0xff));
    for (uVar6 = 0; (short)uVar6 < 2; uVar6 = uVar6 + 1) {
      puVar9 = (ushort *)(local_40[0][0x20] + ((short)uVar6 + 1) * 0x2000);
      FUN_800033a8((int)puVar9,0xff,0x2000);
      puVar9[0xffd] = uVar6;
      FUN_80261278(puVar9,0x1ffc,(short *)(puVar9 + 0xffe),(short *)(puVar9 + 0xfff));
    }
    for (sVar10 = 0; sVar10 < 2; sVar10 = sVar10 + 1) {
      psVar7 = (short *)(local_40[0][0x20] + (sVar10 + 3) * 0x2000);
      FUN_800033a8((int)psVar7,0,0x2000);
      psVar7[2] = sVar10;
      psVar7[3] = *(short *)(local_40[0] + 4) + -5;
      psVar7[4] = 4;
      FUN_80261278((ushort *)(psVar7 + 2),0x1ffc,psVar7,psVar7 + 1);
    }
    if (param_3 == (undefined *)0x0) {
      param_3 = &DAT_8025e5e4;
    }
    local_40[0][0x34] = (int)param_3;
    FUN_80242114(local_40[0][0x20],0xa000);
    local_40[0][10] = 0;
    iVar3 = FUN_8025f378(param_1,local_40[0][3] * local_40[0][10],-0x7fd9d360);
    if (iVar3 < 0) {
      FUN_8025f5e4(local_40[0],iVar3);
    }
  }
  return iVar3;
}

