// Function: FUN_801dde68
// Entry: 801dde68
// Size: 1140 bytes

void FUN_801dde68(void)

{
  ushort uVar1;
  bool bVar2;
  float fVar3;
  ushort *puVar4;
  undefined4 uVar5;
  int iVar6;
  byte bVar7;
  uint uVar8;
  uint uVar9;
  short *psVar10;
  byte local_38 [8];
  undefined4 local_30;
  uint uStack44;
  longlong local_28;
  
  puVar4 = (ushort *)FUN_802860d4();
  psVar10 = *(short **)(puVar4 + 0x5c);
  uVar5 = FUN_8002b9ec();
  if ((*(byte *)(psVar10 + 0x13) & 1) != 0) {
    *(undefined4 *)(psVar10 + 0x10) = 1;
    *puVar4 = 0x3fff;
    uVar1 = *puVar4;
    psVar10[0x12] = ((short)uVar1 >> 0xd) + (ushort)((short)uVar1 < 0 && (uVar1 & 0x1fff) != 0);
    FUN_80035f00(puVar4);
    FUN_801dda28((double)FLOAT_803e5638,puVar4,psVar10);
    FUN_800200e8(*(undefined2 *)(&DAT_80327a60 + psVar10[0x12] * 2),1);
    *(undefined *)(puVar4 + 0x1b) = 0;
    *(byte *)(psVar10 + 0x13) = *(byte *)(psVar10 + 0x13) & 0xfe;
    *(byte *)(psVar10 + 0x13) = *(byte *)(psVar10 + 0x13) | 2;
    (**(code **)(*DAT_803dca68 + 0x40))(1);
    FUN_8011f38c(1);
    (**(code **)(*DAT_803dca4c + 0xc))(0x1e,1);
    *(float *)(psVar10 + 0xc) = FLOAT_803e563c;
    FUN_8000a518(0xf0,1);
  }
  fVar3 = FLOAT_803e5654;
  if ((*(byte *)(psVar10 + 0x13) & 2) != 0) {
    if (*(float *)(psVar10 + 0xc) == FLOAT_803e5654) {
      if (*(float *)(psVar10 + 0xe) == FLOAT_803e5654) {
        iVar6 = FUN_8001ffb4(0x64c);
        if (iVar6 != 0) {
          FUN_800200e8(0x64c,0);
          uVar9 = 0;
          for (bVar7 = 0; bVar7 < 8; bVar7 = bVar7 + 1) {
            iVar6 = FUN_8001ffb4((&DAT_80327a70)[bVar7]);
            uVar8 = uVar9;
            if (iVar6 == 0) {
              uVar8 = uVar9 + 1;
              local_38[uVar9 & 0xff] = bVar7;
            }
            uVar9 = uVar8;
          }
          if ((uVar9 & 0xff) == 0) {
            bVar2 = true;
          }
          else {
            iVar6 = FUN_800221a0(0,(uVar9 & 0xff) - 1);
            bVar7 = local_38[iVar6];
            if ((int)psVar10[0x12] == (uint)bVar7) {
              FUN_800200e8(*(undefined2 *)(&DAT_80327a60 + psVar10[0x12] * 2),1);
            }
            if ((int)psVar10[0x12] != (uint)bVar7) {
              psVar10[0x12] = (ushort)bVar7;
              FUN_8000bb18(puVar4,0x137);
            }
            bVar2 = false;
          }
          if (bVar2) {
            *(float *)(psVar10 + 0xe) = FLOAT_803e5658;
            FUN_8011f6d4(0);
            (**(code **)(*DAT_803dca4c + 8))(0x1e,1);
          }
        }
        if (((int)(short)*puVar4 & 0xffffU) >> 0xd != (int)psVar10[0x12]) {
          uStack44 = (int)(short)*puVar4 ^ 0x80000000;
          local_30 = 0x43300000;
          iVar6 = (int)-(FLOAT_803e565c * FLOAT_803db414 -
                        (float)((double)CONCAT44(0x43300000,uStack44) - DOUBLE_803e5648));
          local_28 = (longlong)iVar6;
          *puVar4 = (ushort)iVar6;
          if (((int)(short)*puVar4 & 0xffffU) >> 0xd == (int)psVar10[0x12]) {
            FUN_800200e8(*(undefined2 *)(&DAT_80327a60 + psVar10[0x12] * 2),1);
          }
        }
      }
      else {
        *(float *)(psVar10 + 0xe) = *(float *)(psVar10 + 0xe) - FLOAT_803db414;
        if (*(float *)(psVar10 + 0xe) <= fVar3) {
          *(float *)(psVar10 + 0xe) = fVar3;
          uVar5 = FUN_8002b9ec();
          (**(code **)(*DAT_803dcaac + 0x2c))();
          (**(code **)(*DAT_803dca50 + 0x1c))(0x42,0,3,0,0,0,0);
          *(undefined *)(puVar4 + 0x1b) = 0xff;
          FUN_80296124(uVar5,0,0,0);
          FUN_80035f20(puVar4);
          FUN_8011f38c(0);
          FUN_800200e8(700,1);
          *(undefined *)(psVar10 + 0x13) = 0;
          FUN_8000a518(0xf0,0);
          goto LAB_801de2c4;
        }
      }
    }
    else {
      *(float *)(psVar10 + 0xc) = *(float *)(psVar10 + 0xc) - FLOAT_803db414;
      if (*(float *)(psVar10 + 0xc) < fVar3) {
        *(float *)(psVar10 + 0xc) = fVar3;
      }
    }
    FUN_80296124(uVar5,puVar4 + 6,puVar4,0);
    *(undefined4 *)(psVar10 + 4) = *(undefined4 *)(puVar4 + 6);
    *(float *)(psVar10 + 6) = FLOAT_803e563c + *(float *)(puVar4 + 8);
    *(undefined4 *)(psVar10 + 8) = *(undefined4 *)(puVar4 + 10);
    *psVar10 = -0x8000 - *puVar4;
    psVar10[1] = puVar4[1];
    psVar10[2] = puVar4[2];
    *(float *)(psVar10 + 10) = FLOAT_803e5660;
    (**(code **)(*DAT_803dca50 + 0x60))(psVar10,0x18);
  }
  if ((*(byte *)(psVar10 + 0x13) & 0x10) != 0) {
    (**(code **)(*DAT_803dcaac + 0x44))(0xe,6);
    *(byte *)(psVar10 + 0x13) = *(byte *)(psVar10 + 0x13) & 0xef;
  }
LAB_801de2c4:
  FUN_80286120();
  return;
}

