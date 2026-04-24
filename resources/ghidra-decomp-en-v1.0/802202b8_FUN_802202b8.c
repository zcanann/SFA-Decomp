// Function: FUN_802202b8
// Entry: 802202b8
// Size: 848 bytes

void FUN_802202b8(void)

{
  short sVar1;
  undefined2 *puVar2;
  uint uVar3;
  short sVar5;
  undefined4 uVar4;
  int iVar6;
  int iVar7;
  int iVar8;
  undefined4 *puVar9;
  undefined8 uVar10;
  
  uVar10 = FUN_802860dc();
  puVar2 = (undefined2 *)((ulonglong)uVar10 >> 0x20);
  iVar6 = (int)uVar10;
  puVar9 = *(undefined4 **)(puVar2 + 0x5c);
  if ((int)*(short *)(iVar6 + 0x1c) != 0) {
    *(float *)(puVar2 + 4) =
         FLOAT_803e6ba8 *
         (float)((double)CONCAT44(0x43300000,(int)*(short *)(iVar6 + 0x1c) ^ 0x80000000) -
                DOUBLE_803e6ba0) * *(float *)(*(int *)(puVar2 + 0x28) + 4);
  }
  if (*(short *)(iVar6 + 0x1e) == -1) {
    *(byte *)((int)puVar9 + 0x41) = *(byte *)((int)puVar9 + 0x41) & 0xbf | 0x40;
  }
  else {
    uVar3 = FUN_8001ffb4();
    *(byte *)((int)puVar9 + 0x41) =
         (byte)((uVar3 & 0xff) << 6) & 0x40 | *(byte *)((int)puVar9 + 0x41) & 0xbf;
  }
  *(code **)(puVar2 + 0x5e) = FUN_80220138;
  iVar7 = *(int *)(puVar2 + 0x26);
  iVar8 = *(int *)(puVar2 + 0x5c);
  FUN_8008016c(iVar8 + 0x24);
  sVar5 = *(short *)(iVar7 + 0x1a);
  if (sVar5 != 0) {
    sVar1 = *(short *)(iVar7 + 0x20);
    if (sVar1 == 0) {
      FUN_80080178(iVar8 + 0x24,(int)(short)(sVar5 * 0x3c));
    }
    else if (sVar1 < 0) {
      sVar5 = FUN_800221a0(1,sVar5 * 0x3c);
      FUN_80080178(iVar8 + 0x24,(int)sVar5);
    }
    else {
      FUN_80080178(iVar8 + 0x24,(int)(short)(sVar1 * 0x3c));
      if (*(short *)(iVar7 + 0x1a) <= *(short *)(iVar7 + 0x20)) {
        *(byte *)(iVar8 + 0x41) = *(byte *)(iVar8 + 0x41) & 0xbf;
      }
    }
  }
  *(undefined2 *)(puVar9 + 0xf) = 0;
  *(undefined2 *)((int)puVar9 + 0x3e) = 0;
  sVar5 = puVar2[0x23];
  if (sVar5 != 0x70a) {
    if (sVar5 < 0x70a) {
      if (sVar5 == 0x6f9) {
        puVar9[0xd] = 10;
        *(undefined *)(puVar9 + 0x10) = 1;
        puVar9[0xe] = FLOAT_803dc340;
        goto LAB_802204d8;
      }
    }
    else {
      if (sVar5 == 0x731) {
        puVar9[0xd] = 0xd;
        *(undefined *)(puVar9 + 0x10) = 2;
        puVar9[0xe] = FLOAT_803e6b74;
        goto LAB_802204d8;
      }
      if (sVar5 < 0x731) {
        if (0x72f < sVar5) {
          puVar9[0xd] = 0xc;
          *(undefined *)(puVar9 + 0x10) = 2;
          puVar9[0xe] = FLOAT_803e6b74;
          goto LAB_802204d8;
        }
      }
      else if (sVar5 < 0x733) {
        puVar9[0xd] = 0xe;
        *(undefined *)(puVar9 + 0x10) = 2;
        puVar9[0xe] = FLOAT_803e6b74;
        goto LAB_802204d8;
      }
    }
  }
  puVar9[0xd] = 9;
  *(undefined *)(puVar9 + 0x10) = 0;
  puVar9[0xe] = -FLOAT_803dc340;
  *(undefined2 *)(puVar9 + 0xf) = 0x32c;
  *(undefined2 *)((int)puVar9 + 0x3e) = 0x32e;
LAB_802204d8:
  *puVar9 = 0;
  puVar9[1] = 0;
  puVar9[2] = 0;
  puVar9[3] = 0;
  puVar9[4] = 0;
  puVar9[5] = 0;
  puVar9[6] = 0;
  puVar9[7] = 0;
  *(undefined *)(puVar9 + 8) = 0;
  puVar2[2] = 0;
  *puVar2 = (short)((int)*(char *)(iVar6 + 0x18) << 8);
  puVar2[1] = (ushort)*(byte *)(iVar6 + 0x19) << 8;
  FUN_80035f20(puVar2);
  *(byte *)((int)puVar9 + 0x41) = *(byte *)((int)puVar9 + 0x41) & 0xef;
  puVar9[0xc] = 0;
  uVar4 = FUN_8001ffb4((int)*(short *)(iVar6 + 0x1e));
  uVar3 = countLeadingZeros(uVar4);
  *(byte *)((int)puVar9 + 0x41) =
       (byte)((uVar3 >> 5 & 0xff) << 7) | *(byte *)((int)puVar9 + 0x41) & 0x7f;
  *(byte *)((int)puVar9 + 0x41) =
       ((*(byte *)(iVar6 + 0x22) & 1) == 0) << 1 | *(byte *)((int)puVar9 + 0x41) & 0xfd;
  *(byte *)((int)puVar9 + 0x41) =
       (*(byte *)(iVar6 + 0x22) & 2) == 0 | *(byte *)((int)puVar9 + 0x41) & 0xfe;
  FUN_8008016c(puVar9 + 10);
  FUN_80080178(puVar9 + 10,0x14);
  FUN_80037200(puVar2,0x4a);
  *(byte *)((int)puVar9 + 0x41) = *(byte *)((int)puVar9 + 0x41) & 0xfb;
  puVar9[0xb] = 0;
  FUN_80286128();
  return;
}

