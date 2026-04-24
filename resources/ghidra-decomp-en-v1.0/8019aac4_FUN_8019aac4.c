// Function: FUN_8019aac4
// Entry: 8019aac4
// Size: 836 bytes

void FUN_8019aac4(int param_1)

{
  bool bVar1;
  uint uVar2;
  int iVar3;
  int *piVar4;
  undefined4 *puVar5;
  int iVar6;
  uint uVar7;
  undefined4 local_18;
  int local_14;
  int local_10 [2];
  
  local_18 = 0;
  if (DAT_803dbe08 != '\0') {
    DAT_803ddb0c = (**(code **)(*DAT_803dca9c + 0x40))(8);
    DAT_803dbe08 = '\0';
  }
  DAT_803ddb08 = '\0';
LAB_8019add4:
  do {
    while( true ) {
      iVar3 = FUN_800374ec(param_1,local_10,&local_14,&local_18);
      if (iVar3 == 0) {
        return;
      }
      if (local_10[0] == 0xf0008) break;
      if (local_10[0] < 0xf0008) {
        if (local_10[0] == 0xf0004) {
          if (*(char *)(local_14 + 0xac) == *(char *)(param_1 + 0xac)) {
            bVar1 = false;
            piVar4 = &DAT_803ac7d8;
            iVar3 = (int)DAT_803ddb09;
            if (0 < iVar3) {
              do {
                if (*piVar4 == local_14) {
                  *(short *)(piVar4 + 1) = (short)local_18;
                  bVar1 = true;
                }
                piVar4 = piVar4 + 2;
                iVar3 = iVar3 + -1;
              } while (iVar3 != 0);
            }
            if (!bVar1) {
              iVar3 = (int)DAT_803ddb09;
              (&DAT_803ac7d8)[iVar3 * 2] = local_14;
              (&DAT_803ac7de)[iVar3 * 8] = 0;
              DAT_803ddb09 = DAT_803ddb09 + '\x01';
              (&DAT_803ac7dc)[iVar3 * 4] = (short)local_18;
            }
            FUN_800378c4(local_14,0xf0003,param_1,0);
          }
        }
        else if (local_10[0] < 0xf0004) goto LAB_8019ada0;
      }
      else {
LAB_8019ada0:
        iVar3 = DAT_803ddb08 * 0xc;
        *(int *)(&DAT_803ac87c + iVar3) = local_14;
        *(int *)(&DAT_803ac878 + iVar3) = local_10[0];
        *(undefined4 *)(&DAT_803ac880 + iVar3) = local_18;
        DAT_803ddb08 = DAT_803ddb08 + '\x01';
      }
    }
    iVar3 = 0;
    for (piVar4 = &DAT_803ac7d8; (iVar3 < DAT_803ddb09 && (*piVar4 != local_14));
        piVar4 = piVar4 + 2) {
      iVar3 = iVar3 + 1;
    }
    DAT_803ddb09 = DAT_803ddb09 + -1;
    iVar6 = (int)DAT_803ddb09;
    puVar5 = &DAT_803ac7d8 + iVar6 * 2;
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
    if (uVar2 == 0) goto LAB_8019add4;
  }
  do {
    puVar5[-2] = *puVar5;
    *(undefined2 *)(puVar5 + -1) = *(undefined2 *)(puVar5 + 1);
    *(undefined *)((int)puVar5 + -2) = *(undefined *)((int)puVar5 + 6);
    puVar5 = puVar5 + -2;
    uVar2 = uVar2 - 1;
  } while (uVar2 != 0);
  goto LAB_8019add4;
}

