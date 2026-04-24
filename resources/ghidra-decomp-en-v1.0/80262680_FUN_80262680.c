// Function: FUN_80262680
// Entry: 80262680
// Size: 1624 bytes

int FUN_80262680(int param_1,undefined2 param_2,undefined *param_3)

{
  ushort uVar1;
  ulonglong uVar2;
  uint uVar3;
  int iVar4;
  undefined4 uVar5;
  uint extraout_r4;
  uint extraout_r4_00;
  uint extraout_r4_01;
  uint extraout_r4_02;
  uint extraout_r4_03;
  uint extraout_r4_04;
  uint extraout_r4_05;
  uint extraout_r4_06;
  uint extraout_r4_07;
  char *pcVar6;
  char *pcVar7;
  int iVar8;
  short sVar9;
  ulonglong uVar10;
  int local_40 [2];
  
  iVar4 = FUN_8025edc8(param_1,local_40);
  if (-1 < iVar4) {
    iVar8 = *(int *)(local_40[0] + 0x80);
    FUN_800033a8(iVar8,0xff,0x2000);
    uVar1 = read_volatile_2(DAT_cc00206e);
    *(undefined2 *)(iVar8 + 0x24) = param_2;
    iVar4 = FUN_80245188();
    *(undefined4 *)(iVar8 + 0x14) = *(undefined4 *)(iVar4 + 0xc);
    *(uint *)(iVar8 + 0x18) = (uint)*(byte *)(iVar4 + 0x12);
    FUN_80245548(0);
    uVar10 = FUN_80246c50();
    uVar2 = uVar10 >> 0x20;
    uVar5 = (undefined4)uVar10;
    iVar4 = FUN_802451e4();
    pcVar7 = (char *)(iVar4 + param_1 * 0xc);
    sVar9 = 0;
    pcVar6 = pcVar7;
    while( true ) {
      if (3 < sVar9) break;
      uVar3 = (int)uVar10 * 0x41c64e6d;
      uVar10 = FUN_80286490((int)(uVar10 >> 0x20) * 0x41c64e6d +
                            (int)((uVar10 & 0xffffffff) * 0x41c64e6d >> 0x20) +
                            (uint)(0xffffcfc6 < uVar3),uVar3 + 0x3039,0x10);
      *(char *)(iVar8 + sVar9) = (char)uVar10 + *pcVar6;
      uVar3 = (int)uVar10 * 0x41c64e6d;
      FUN_80286490((int)(uVar10 >> 0x20) * 0x41c64e6d +
                   (int)((uVar10 & 0xffffffff) * 0x41c64e6d >> 0x20) + (uint)(0xffffcfc6 < uVar3),
                   uVar3 + 0x3039,0x10);
      uVar3 = (extraout_r4 & 0x7fff) * 0x41c64e6d;
      uVar10 = FUN_80286490((int)((ulonglong)(extraout_r4 & 0x7fff) * 0x41c64e6d >> 0x20) +
                            (uint)(0xffffcfc6 < uVar3),uVar3 + 0x3039,0x10);
      uVar3 = (int)uVar10 * 0x41c64e6d;
      *(char *)(iVar8 + (short)(sVar9 + 1)) = (char)uVar10 + pcVar7[(short)(sVar9 + 1)];
      FUN_80286490((int)(uVar10 >> 0x20) * 0x41c64e6d +
                   (int)((uVar10 & 0xffffffff) * 0x41c64e6d >> 0x20) + (uint)(0xffffcfc6 < uVar3),
                   uVar3 + 0x3039,0x10);
      uVar3 = (extraout_r4_00 & 0x7fff) * 0x41c64e6d;
      uVar10 = FUN_80286490((int)((ulonglong)(extraout_r4_00 & 0x7fff) * 0x41c64e6d >> 0x20) +
                            (uint)(0xffffcfc6 < uVar3),uVar3 + 0x3039,0x10);
      uVar3 = (int)uVar10 * 0x41c64e6d;
      *(char *)(iVar8 + (short)(sVar9 + 2)) = (char)uVar10 + pcVar7[(short)(sVar9 + 2)];
      FUN_80286490((int)(uVar10 >> 0x20) * 0x41c64e6d +
                   (int)((uVar10 & 0xffffffff) * 0x41c64e6d >> 0x20) + (uint)(0xffffcfc6 < uVar3),
                   uVar3 + 0x3039,0x10);
      uVar3 = (extraout_r4_01 & 0x7fff) * 0x41c64e6d;
      uVar10 = FUN_80286490((int)((ulonglong)(extraout_r4_01 & 0x7fff) * 0x41c64e6d >> 0x20) +
                            (uint)(0xffffcfc6 < uVar3),uVar3 + 0x3039,0x10);
      uVar3 = (int)uVar10 * 0x41c64e6d;
      *(char *)(iVar8 + (short)(sVar9 + 3)) = (char)uVar10 + pcVar7[(short)(sVar9 + 3)];
      FUN_80286490((int)(uVar10 >> 0x20) * 0x41c64e6d +
                   (int)((uVar10 & 0xffffffff) * 0x41c64e6d >> 0x20) + (uint)(0xffffcfc6 < uVar3),
                   uVar3 + 0x3039,0x10);
      uVar3 = (extraout_r4_02 & 0x7fff) * 0x41c64e6d;
      uVar10 = FUN_80286490((int)((ulonglong)(extraout_r4_02 & 0x7fff) * 0x41c64e6d >> 0x20) +
                            (uint)(0xffffcfc6 < uVar3),uVar3 + 0x3039,0x10);
      uVar3 = (int)uVar10 * 0x41c64e6d;
      *(char *)(iVar8 + (short)(sVar9 + 4)) = (char)uVar10 + pcVar7[(short)(sVar9 + 4)];
      FUN_80286490((int)(uVar10 >> 0x20) * 0x41c64e6d +
                   (int)((uVar10 & 0xffffffff) * 0x41c64e6d >> 0x20) + (uint)(0xffffcfc6 < uVar3),
                   uVar3 + 0x3039,0x10);
      uVar3 = (extraout_r4_03 & 0x7fff) * 0x41c64e6d;
      uVar10 = FUN_80286490((int)((ulonglong)(extraout_r4_03 & 0x7fff) * 0x41c64e6d >> 0x20) +
                            (uint)(0xffffcfc6 < uVar3),uVar3 + 0x3039,0x10);
      uVar3 = (int)uVar10 * 0x41c64e6d;
      *(char *)(iVar8 + (short)(sVar9 + 5)) = (char)uVar10 + pcVar7[(short)(sVar9 + 5)];
      FUN_80286490((int)(uVar10 >> 0x20) * 0x41c64e6d +
                   (int)((uVar10 & 0xffffffff) * 0x41c64e6d >> 0x20) + (uint)(0xffffcfc6 < uVar3),
                   uVar3 + 0x3039,0x10);
      uVar3 = (extraout_r4_04 & 0x7fff) * 0x41c64e6d;
      uVar10 = FUN_80286490((int)((ulonglong)(extraout_r4_04 & 0x7fff) * 0x41c64e6d >> 0x20) +
                            (uint)(0xffffcfc6 < uVar3),uVar3 + 0x3039,0x10);
      uVar3 = (int)uVar10 * 0x41c64e6d;
      *(char *)(iVar8 + (short)(sVar9 + 6)) = (char)uVar10 + pcVar7[(short)(sVar9 + 6)];
      FUN_80286490((int)(uVar10 >> 0x20) * 0x41c64e6d +
                   (int)((uVar10 & 0xffffffff) * 0x41c64e6d >> 0x20) + (uint)(0xffffcfc6 < uVar3),
                   uVar3 + 0x3039,0x10);
      uVar3 = (extraout_r4_05 & 0x7fff) * 0x41c64e6d;
      uVar10 = FUN_80286490((int)((ulonglong)(extraout_r4_05 & 0x7fff) * 0x41c64e6d >> 0x20) +
                            (uint)(0xffffcfc6 < uVar3),uVar3 + 0x3039,0x10);
      uVar3 = (int)uVar10 * 0x41c64e6d;
      *(char *)(iVar8 + (short)(sVar9 + 7)) = (char)uVar10 + pcVar7[(short)(sVar9 + 7)];
      FUN_80286490((int)(uVar10 >> 0x20) * 0x41c64e6d +
                   (int)((uVar10 & 0xffffffff) * 0x41c64e6d >> 0x20) + (uint)(0xffffcfc6 < uVar3),
                   uVar3 + 0x3039,0x10);
      uVar10 = (ulonglong)(extraout_r4_06 & 0x7fff);
      pcVar6 = pcVar6 + 8;
      sVar9 = sVar9 + 8;
    }
    pcVar7 = pcVar7 + sVar9;
    while( true ) {
      if (0xb < sVar9) break;
      uVar3 = (int)uVar10 * 0x41c64e6d;
      uVar10 = FUN_80286490((int)(uVar10 >> 0x20) * 0x41c64e6d +
                            (int)((uVar10 & 0xffffffff) * 0x41c64e6d >> 0x20) +
                            (uint)(0xffffcfc6 < uVar3),uVar3 + 0x3039,0x10);
      *(char *)(iVar8 + sVar9) = (char)uVar10 + *pcVar7;
      uVar3 = (int)uVar10 * 0x41c64e6d;
      FUN_80286490((int)(uVar10 >> 0x20) * 0x41c64e6d +
                   (int)((uVar10 & 0xffffffff) * 0x41c64e6d >> 0x20) + (uint)(0xffffcfc6 < uVar3),
                   uVar3 + 0x3039,0x10);
      uVar10 = (ulonglong)(extraout_r4_07 & 0x7fff);
      pcVar7 = pcVar7 + 1;
      sVar9 = sVar9 + 1;
    }
    FUN_8024556c(0);
    *(uint *)(iVar8 + 0x1c) = (uint)uVar1;
    *(undefined4 *)(iVar8 + 0x10) = uVar5;
    *(int *)(iVar8 + 0xc) = (int)uVar2;
    *(undefined2 *)(iVar8 + 0x20) = 0;
    *(undefined2 *)(iVar8 + 0x22) = *(undefined2 *)(local_40[0] + 8);
    FUN_80260b14(iVar8,0x1fc,iVar8 + 0x1fc,iVar8 + 0x1fe);
    for (sVar9 = 0; sVar9 < 2; sVar9 = sVar9 + 1) {
      iVar4 = *(int *)(local_40[0] + 0x80) + (sVar9 + 1) * 0x2000;
      FUN_800033a8(iVar4,0xff,0x2000);
      *(short *)(iVar4 + 0x1ffa) = sVar9;
      FUN_80260b14(iVar4,0x1ffc,iVar4 + 0x1ffc,iVar4 + 0x1ffe);
    }
    for (sVar9 = 0; sVar9 < 2; sVar9 = sVar9 + 1) {
      iVar4 = *(int *)(local_40[0] + 0x80) + (sVar9 + 3) * 0x2000;
      FUN_800033a8(iVar4,0,0x2000);
      *(short *)(iVar4 + 4) = sVar9;
      *(short *)(iVar4 + 6) = *(short *)(local_40[0] + 0x10) + -5;
      *(undefined2 *)(iVar4 + 8) = 4;
      FUN_80260b14(iVar4 + 4,0x1ffc,iVar4,iVar4 + 2);
    }
    if (param_3 == (undefined *)0x0) {
      param_3 = &DAT_8025de80;
    }
    *(undefined **)(local_40[0] + 0xd0) = param_3;
    FUN_80241a1c(*(undefined4 *)(local_40[0] + 0x80),0xa000);
    *(undefined4 *)(local_40[0] + 0x28) = 0;
    iVar4 = FUN_8025ec14(param_1,*(int *)(local_40[0] + 0xc) * *(int *)(local_40[0] + 0x28),
                         &LAB_8026253c);
    if (iVar4 < 0) {
      FUN_8025ee80(local_40[0],iVar4);
    }
  }
  return iVar4;
}

