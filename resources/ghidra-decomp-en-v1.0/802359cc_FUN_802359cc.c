// Function: FUN_802359cc
// Entry: 802359cc
// Size: 1220 bytes

void FUN_802359cc(int param_1)

{
  uint uVar1;
  float fVar2;
  float fVar3;
  int iVar4;
  int iVar5;
  int *piVar6;
  int *piVar7;
  double dVar8;
  undefined auStack88 [4];
  undefined auStack84 [4];
  undefined auStack80 [4];
  undefined auStack76 [12];
  float local_40;
  float local_3c;
  float local_38;
  undefined auStack52 [28];
  longlong local_18;
  
  piVar6 = *(int **)(param_1 + 0xb8);
  FUN_8002fa48((double)(float)piVar6[0x11],(double)FLOAT_803db414,param_1,auStack52);
  if (*(short *)(piVar6 + 0x16) != 0) {
    if (FLOAT_803e72f8 < (float)piVar6[0xf]) {
      piVar6[0xf] = (int)((float)piVar6[0xf] - FLOAT_803db414);
    }
    if (FLOAT_803e730c < (float)piVar6[0x11]) {
      piVar6[0x11] = (int)((float)piVar6[0x11] - FLOAT_803e7310);
    }
    if ((*(ushort *)(piVar6 + 0x16) & 0x80) != 0) {
      FUN_802357e8(param_1,piVar6);
    }
    if ((*(ushort *)(piVar6 + 0x16) & 0x20) != 0) {
      if ((*(ushort *)(piVar6 + 0x16) & 0xc0) == 0) {
        iVar4 = FUN_80037b40(param_1,8,0xff,0xff,0x78,0x129,piVar6 + 0x14);
      }
      else {
        iVar4 = FUN_80036770(param_1,auStack80,auStack84,auStack88,&local_40,&local_3c,&local_38);
      }
      if (FLOAT_803e72f8 <= (float)piVar6[0x13]) {
        piVar6[0x13] = (int)((float)piVar6[0x13] - FLOAT_803db414);
      }
      if (((iVar4 != 0) && (iVar4 != 0x11)) && ((float)piVar6[0x13] <= FLOAT_803e72f8)) {
        if ((*(ushort *)(piVar6 + 0x16) & 0xc0) != 0) {
          local_40 = local_40 + FLOAT_803dcdd8;
          local_38 = local_38 + FLOAT_803dcddc;
          FUN_8009a1dc((double)FLOAT_803e7314,param_1,auStack76,1,0);
          FUN_8002ac30(param_1,0xf,200,0,0,1);
        }
        if ((*(ushort *)(piVar6 + 0x16) & 0xf) != 0) {
          local_38 = (float)piVar6[0x12];
          iVar5 = (uint)*(ushort *)((int)piVar6 + 0x5a) * 0x10;
          local_40 = local_38 * *(float *)(&DAT_8032bbe0 + iVar5);
          local_3c = local_38 * *(float *)(&DAT_8032bbe4 + iVar5);
          local_38 = local_38 * *(float *)(&DAT_8032bbe8 + iVar5);
          FUN_80021ac8(param_1,&local_40);
          FUN_80096c94((double)((float)piVar6[0x12] *
                               *(float *)(&DAT_8032bbec +
                                         (uint)*(ushort *)((int)piVar6 + 0x5a) * 0x10)),param_1,
                       *(ushort *)(piVar6 + 0x16) & 0xf,0x14,auStack76,0);
        }
        piVar6[0x11] = (int)FLOAT_803e7318;
        piVar6[0x13] = (int)FLOAT_803e731c;
        if (((*(ushort *)(piVar6 + 0x16) & 0x80) != 0) && (iVar4 != 0)) {
          iVar4 = 0;
          piVar7 = piVar6;
          do {
            if ((*piVar7 != 0) &&
               (iVar5 = (**(code **)(**(int **)(*piVar7 + 0x68) + 0x28))(), 1 < iVar5)) {
              FUN_80036450(piVar6[iVar4],param_1,0xe,1,0);
              break;
            }
            piVar7 = piVar7 + 1;
            iVar4 = iVar4 + 1;
          } while (iVar4 < 3);
        }
      }
    }
    iVar4 = FUN_8002b9ec();
    if (((iVar4 != 0) && ((*(ushort *)(piVar6 + 0x16) & 0x100) == 0)) &&
       ((*(ushort *)(piVar6 + 0x16) & 0xf) != 0)) {
      fVar2 = *(float *)(param_1 + 0xc) - *(float *)(iVar4 + 0xc);
      fVar3 = *(float *)(param_1 + 0x14) - *(float *)(iVar4 + 0x14);
      dVar8 = (double)FUN_802931a0((double)(fVar2 * fVar2 + fVar3 * fVar3));
      uVar1 = (uint)dVar8;
      local_18 = (longlong)(int)uVar1;
      if ((uVar1 & 0xffff) < (uint)*(ushort *)(piVar6 + 0x15)) {
        if ((((*(ushort *)(piVar6 + 0x16) & 0x10) != 0) &&
            ((uint)*(ushort *)(piVar6 + 0x15) <= (uint)*(ushort *)((int)piVar6 + 0x56))) &&
           ((float)piVar6[0xf] <= FLOAT_803e72f8)) {
          local_38 = (float)piVar6[0x12];
          iVar4 = (uint)*(ushort *)((int)piVar6 + 0x5a) * 0x10;
          local_40 = local_38 * *(float *)(&DAT_8032bbe0 + iVar4);
          local_3c = local_38 * *(float *)(&DAT_8032bbe4 + iVar4);
          local_38 = local_38 * *(float *)(&DAT_8032bbe8 + iVar4);
          FUN_80021ac8(param_1,&local_40);
          FUN_80096c94((double)((float)piVar6[0x12] *
                               *(float *)(&DAT_8032bbec +
                                         (uint)*(ushort *)((int)piVar6 + 0x5a) * 0x10)),param_1,
                       *(ushort *)(piVar6 + 0x16) & 0xf,0x14,auStack76,1);
          piVar6[0xf] = (int)FLOAT_803e7320;
        }
        piVar6[0x10] = (int)((float)piVar6[0x10] - FLOAT_803db414);
        if ((float)piVar6[0x10] <= FLOAT_803e72f8) {
          local_38 = (float)piVar6[0x12];
          iVar4 = (uint)*(ushort *)((int)piVar6 + 0x5a) * 0x10;
          local_40 = local_38 * *(float *)(&DAT_8032bbe0 + iVar4);
          local_3c = local_38 * *(float *)(&DAT_8032bbe4 + iVar4);
          local_38 = local_38 * *(float *)(&DAT_8032bbe8 + iVar4);
          FUN_80021ac8(param_1,&local_40);
          FUN_80096c94((double)((float)piVar6[0x12] *
                               *(float *)(&DAT_8032bbec +
                                         (uint)*(ushort *)((int)piVar6 + 0x5a) * 0x10)),param_1,
                       *(ushort *)(piVar6 + 0x16) & 0xf,1,auStack76,0);
          piVar6[0x10] = (int)((float)piVar6[0x10] + FLOAT_803e7324);
        }
      }
      *(short *)((int)piVar6 + 0x56) = (short)uVar1;
    }
  }
  return;
}

