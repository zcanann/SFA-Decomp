// Function: FUN_8019b040
// Entry: 8019b040
// Size: 836 bytes

void FUN_8019b040(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 uint param_9)

{
  bool bVar1;
  uint uVar2;
  int iVar3;
  uint *puVar4;
  undefined4 *puVar5;
  int iVar6;
  undefined4 in_r8;
  undefined4 in_r9;
  undefined4 in_r10;
  uint uVar7;
  undefined8 extraout_f1;
  uint local_18;
  uint local_14;
  uint local_10 [2];
  
  local_18 = 0;
  if (DAT_803dca70 != '\0') {
    DAT_803de78c = (**(code **)(*DAT_803dd71c + 0x40))(8);
    DAT_803dca70 = '\0';
    param_1 = extraout_f1;
  }
  DAT_803de788 = '\0';
LAB_8019b350:
  do {
    while( true ) {
      iVar3 = FUN_800375e4(param_9,local_10,&local_14,&local_18);
      if (iVar3 == 0) {
        return;
      }
      if (local_10[0] == 0xf0008) break;
      if ((int)local_10[0] < 0xf0008) {
        if (local_10[0] == 0xf0004) {
          if (*(char *)(local_14 + 0xac) == *(char *)(param_9 + 0xac)) {
            bVar1 = false;
            puVar4 = &DAT_803ad438;
            iVar3 = (int)DAT_803de789;
            if (0 < iVar3) {
              do {
                if (*puVar4 == local_14) {
                  *(short *)(puVar4 + 1) = (short)local_18;
                  bVar1 = true;
                }
                puVar4 = puVar4 + 2;
                iVar3 = iVar3 + -1;
              } while (iVar3 != 0);
            }
            if (!bVar1) {
              iVar3 = (int)DAT_803de789;
              (&DAT_803ad438)[iVar3 * 2] = local_14;
              (&DAT_803ad43e)[iVar3 * 8] = 0;
              DAT_803de789 = DAT_803de789 + '\x01';
              (&DAT_803ad43c)[iVar3 * 4] = (short)local_18;
            }
            FUN_800379bc(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,local_14,
                         0xf0003,param_9,0,0xf0004,in_r8,in_r9,in_r10);
          }
        }
        else if ((int)local_10[0] < 0xf0004) goto LAB_8019b31c;
      }
      else {
LAB_8019b31c:
        iVar3 = DAT_803de788 * 0xc;
        *(uint *)(&DAT_803ad4dc + iVar3) = local_14;
        *(uint *)(&DAT_803ad4d8 + iVar3) = local_10[0];
        *(uint *)(&DAT_803ad4e0 + iVar3) = local_18;
        DAT_803de788 = DAT_803de788 + '\x01';
      }
    }
    iVar3 = 0;
    for (puVar4 = &DAT_803ad438; (iVar3 < DAT_803de789 && (*puVar4 != local_14));
        puVar4 = puVar4 + 2) {
      iVar3 = iVar3 + 1;
    }
    DAT_803de789 = DAT_803de789 + -1;
    iVar6 = (int)DAT_803de789;
    puVar5 = &DAT_803ad438 + iVar6 * 2;
    uVar2 = iVar6 - iVar3;
  } while (iVar6 <= iVar3);
  uVar7 = uVar2 >> 3;
  if (uVar7 != 0) {
    do {
      puVar5[-2] = *puVar5;
      *(undefined2 *)(puVar5 + -1) = *(undefined2 *)(puVar5 + 1);
      *(undefined *)((int)puVar5 + -2) = *(undefined *)((int)puVar5 + 6);
      puVar5[-4] = puVar5[-2];
      *(undefined2 *)(puVar5 + -3) = *(undefined2 *)(puVar5 + -1);
      *(undefined *)((int)puVar5 + -10) = *(undefined *)((int)puVar5 + -2);
      puVar5[-6] = puVar5[-4];
      *(undefined2 *)(puVar5 + -5) = *(undefined2 *)(puVar5 + -3);
      *(undefined *)((int)puVar5 + -0x12) = *(undefined *)((int)puVar5 + -10);
      puVar5[-8] = puVar5[-6];
      *(undefined2 *)(puVar5 + -7) = *(undefined2 *)(puVar5 + -5);
      *(undefined *)((int)puVar5 + -0x1a) = *(undefined *)((int)puVar5 + -0x12);
      puVar5[-10] = puVar5[-8];
      *(undefined2 *)(puVar5 + -9) = *(undefined2 *)(puVar5 + -7);
      *(undefined *)((int)puVar5 + -0x22) = *(undefined *)((int)puVar5 + -0x1a);
      puVar5[-0xc] = puVar5[-10];
      *(undefined2 *)(puVar5 + -0xb) = *(undefined2 *)(puVar5 + -9);
      *(undefined *)((int)puVar5 + -0x2a) = *(undefined *)((int)puVar5 + -0x22);
      puVar5[-0xe] = puVar5[-0xc];
      *(undefined2 *)(puVar5 + -0xd) = *(undefined2 *)(puVar5 + -0xb);
      *(undefined *)((int)puVar5 + -0x32) = *(undefined *)((int)puVar5 + -0x2a);
      puVar5[-0x10] = puVar5[-0xe];
      *(undefined2 *)(puVar5 + -0xf) = *(undefined2 *)(puVar5 + -0xd);
      *(undefined *)((int)puVar5 + -0x3a) = *(undefined *)((int)puVar5 + -0x32);
      puVar5 = puVar5 + -0x10;
      uVar7 = uVar7 - 1;
    } while (uVar7 != 0);
    uVar2 = uVar2 & 7;
    if (uVar2 == 0) goto LAB_8019b350;
  }
  do {
    puVar5[-2] = *puVar5;
    *(undefined2 *)(puVar5 + -1) = *(undefined2 *)(puVar5 + 1);
    *(undefined *)((int)puVar5 + -2) = *(undefined *)((int)puVar5 + 6);
    puVar5 = puVar5 + -2;
    uVar2 = uVar2 - 1;
  } while (uVar2 != 0);
  goto LAB_8019b350;
}

