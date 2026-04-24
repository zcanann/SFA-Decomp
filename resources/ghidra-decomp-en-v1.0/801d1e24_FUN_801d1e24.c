// Function: FUN_801d1e24
// Entry: 801d1e24
// Size: 2452 bytes

void FUN_801d1e24(void)

{
  float fVar1;
  float fVar2;
  float fVar3;
  int iVar4;
  int iVar5;
  int iVar6;
  uint uVar7;
  char cVar8;
  int iVar9;
  float *pfVar10;
  double dVar11;
  undefined auStack88 [4];
  undefined auStack84 [4];
  undefined auStack80 [4];
  undefined auStack76 [12];
  float local_40;
  float local_3c;
  float local_38 [2];
  double local_30;
  undefined4 local_28;
  uint uStack36;
  double local_20;
  
  iVar4 = FUN_802860dc();
  pfVar10 = *(float **)(iVar4 + 0xb8);
  iVar5 = FUN_8002b9ec();
  iVar9 = *(int *)(iVar4 + 0x4c);
  FUN_80035dac(iVar4);
  *(byte *)(iVar4 + 0xaf) = *(byte *)(iVar4 + 0xaf) | 8;
  *(byte *)((int)pfVar10 + 0x37) = *(byte *)((int)pfVar10 + 0x37) | 4;
  iVar6 = FUN_8002b044(iVar4);
  if (iVar6 == 0) {
    if ((*(ushort *)(iVar5 + 0xb0) & 0x1000) == 0) {
      switch(*(undefined *)((int)pfVar10 + 0x36)) {
      default:
        *(byte *)(iVar4 + 0xaf) = *(byte *)(iVar4 + 0xaf) & 0xf7;
        fVar1 = *(float *)(iVar5 + 0xc) - *(float *)(iVar4 + 0xc);
        fVar2 = *(float *)(iVar5 + 0x10) - *(float *)(iVar4 + 0x10);
        fVar3 = *(float *)(iVar5 + 0x14) - *(float *)(iVar4 + 0x14);
        dVar11 = (double)FUN_802931a0((double)(fVar3 * fVar3 + fVar1 * fVar1 + fVar2 * fVar2));
        local_30 = (double)(longlong)(int)dVar11;
        uStack36 = (uint)*(byte *)(iVar9 + 0x1e);
        local_28 = 0x43300000;
        uVar7 = (uint)(FLOAT_803e5338 *
                      (float)((double)CONCAT44(0x43300000,uStack36) - DOUBLE_803e5348));
        local_20 = (double)(longlong)(int)uVar7;
        if ((((int)dVar11 & 0xffffU) < (uVar7 & 0xffff)) &&
           (dVar11 = (double)FUN_8029610c(iVar5), (double)FLOAT_803e533c <= dVar11)) {
          *(byte *)((int)pfVar10 + 0x37) = *(byte *)((int)pfVar10 + 0x37) & 0xfe;
          *(undefined *)((int)pfVar10 + 0x36) = 3;
          *pfVar10 = FLOAT_803e52fc;
          FUN_8000bb18(iVar4,0x48e);
        }
        break;
      case 1:
        *(byte *)((int)pfVar10 + 0x37) = *(byte *)((int)pfVar10 + 0x37) & 0xfb;
        if (pfVar10[1] < *(float *)(iVar4 + 8)) {
          pfVar10[4] = pfVar10[4] / FLOAT_803e5328;
        }
        if (pfVar10[4] < FLOAT_803e52f8) {
          pfVar10[4] = FLOAT_803e52fc;
        }
        *pfVar10 = *pfVar10 + FLOAT_803db414;
        *(float *)(iVar4 + 8) = pfVar10[4] * FLOAT_803db414 + *(float *)(iVar4 + 8);
        if (pfVar10[2] < *pfVar10) {
          *(undefined *)((int)pfVar10 + 0x36) = 0;
        }
        break;
      case 2:
        *(byte *)((int)pfVar10 + 0x37) = *(byte *)((int)pfVar10 + 0x37) & 0xfb;
        if ((*(byte *)((int)pfVar10 + 0x37) & 2) != 0) {
          iVar5 = (uint)*(byte *)(iVar4 + 0x36) + (uint)DAT_803db410 * -4;
          if (iVar5 < 0) {
            iVar5 = 0;
          }
          *(char *)(iVar4 + 0x36) = (char)iVar5;
          *pfVar10 = *pfVar10 + FLOAT_803db414;
          local_30 = (double)CONCAT44(0x43300000,(int)*(short *)(pfVar10 + 0xd) ^ 0x80000000);
          if ((float)(local_30 - DOUBLE_803e5308) < *pfVar10) {
            FUN_801d1bfc(iVar4,pfVar10,1);
            *(undefined *)((int)pfVar10 + 0x36) = 1;
          }
        }
        break;
      case 3:
        *(byte *)(iVar4 + 0xaf) = *(byte *)(iVar4 + 0xaf) & 0xf7;
        FUN_8000da58(iVar4,0x9c);
        if ((*(byte *)((int)pfVar10 + 0x37) & 2) != 0) {
          *(undefined *)((int)pfVar10 + 0x36) = 4;
        }
        break;
      case 4:
        *(byte *)(iVar4 + 0xaf) = *(byte *)(iVar4 + 0xaf) & 0xf7;
        pfVar10[0xb] = FLOAT_803e5320 * FLOAT_803db414 + pfVar10[0xb];
        FUN_8000da58(iVar4,0x9a);
        if (((((*(byte *)((int)pfVar10 + 0x37) & 1) == 0) &&
             (dVar11 = (double)FUN_80021704(iVar4 + 0x18,iVar5 + 0x18),
             dVar11 <= (double)pfVar10[0xb])) && (iVar6 = FUN_80296458(iVar5), iVar6 == 0)) &&
           ((iVar6 = FUN_80296448(iVar5), iVar6 == 0 && ((*(ushort *)(iVar5 + 0xb0) & 0x1000) == 0))
           )) {
          FUN_80036450(iVar5,iVar4,0x16,1,0);
          *(byte *)((int)pfVar10 + 0x37) = *(byte *)((int)pfVar10 + 0x37) | 1;
        }
        if (FLOAT_803e531c < pfVar10[0xb]) {
          pfVar10[0xb] = FLOAT_803e531c;
        }
        *pfVar10 = *pfVar10 + FLOAT_803db414;
        if (FLOAT_803e5324 < *pfVar10) {
          *pfVar10 = FLOAT_803e52fc;
          *(undefined *)((int)pfVar10 + 0x36) = 5;
        }
        local_40 = pfVar10[8];
        local_3c = pfVar10[9];
        local_38[0] = pfVar10[10];
        for (cVar8 = '\x01'; cVar8 != '\0'; cVar8 = cVar8 + -1) {
          (**(code **)(*DAT_803dca88 + 8))(iVar4,0x3eb,auStack76,0x200001,0xffffffff,0);
        }
        break;
      case 5:
        *(byte *)(iVar4 + 0xaf) = *(byte *)(iVar4 + 0xaf) & 0xf7;
        *pfVar10 = *pfVar10 + FLOAT_803db414;
        local_30 = (double)CONCAT44(0x43300000,(uint)*(ushort *)(iVar9 + 0x18));
        if (((float)(local_30 - DOUBLE_803e5348) < *pfVar10) &&
           ((*(byte *)((int)pfVar10 + 0x37) & 2) != 0)) {
          *(undefined *)((int)pfVar10 + 0x36) = 0;
          pfVar10[0xb] = FLOAT_803e52fc;
          *(byte *)((int)pfVar10 + 0x37) = *(byte *)((int)pfVar10 + 0x37) & 0xfe;
        }
        break;
      case 6:
        FUN_8000da58(iVar4,0x9a);
        *(byte *)((int)pfVar10 + 0x37) = *(byte *)((int)pfVar10 + 0x37) & 0xfb;
        pfVar10[0xb] = FLOAT_803e5318 * FLOAT_803db414 + pfVar10[0xb];
        if (FLOAT_803e531c < pfVar10[0xb]) {
          pfVar10[0xb] = FLOAT_803e531c;
        }
        if (((((*(byte *)((int)pfVar10 + 0x37) & 1) == 0) &&
             (dVar11 = (double)FUN_80021704(iVar4 + 0x18,iVar5 + 0x18),
             dVar11 <= (double)pfVar10[0xb])) && (iVar6 = FUN_80296458(iVar5), iVar6 == 0)) &&
           ((iVar6 = FUN_80296448(iVar5), iVar6 == 0 && ((*(ushort *)(iVar5 + 0xb0) & 0x1000) == 0))
           )) {
          FUN_80036450(iVar5,iVar4,0x16,1,0);
          *(byte *)((int)pfVar10 + 0x37) = *(byte *)((int)pfVar10 + 0x37) | 1;
        }
        if ((*(byte *)((int)pfVar10 + 0x37) & 2) != 0) {
          *pfVar10 = FLOAT_803e52fc;
          *(undefined *)((int)pfVar10 + 0x36) = 2;
        }
        local_40 = pfVar10[8];
        local_3c = pfVar10[9];
        local_38[0] = pfVar10[10];
        for (cVar8 = '\x01'; cVar8 != '\0'; cVar8 = cVar8 + -1) {
          (**(code **)(*DAT_803dca88 + 8))(iVar4,0x3eb,auStack76,0x200001,0xffffffff,0);
        }
        break;
      case 9:
        if (*pfVar10 <= FLOAT_803e52fc) {
          uVar7 = FUN_800221a0(0xf0,300);
          local_30 = (double)CONCAT44(0x43300000,uVar7 ^ 0x80000000);
          *pfVar10 = (float)(local_30 - DOUBLE_803e5308);
        }
        if ((*(byte *)((int)pfVar10 + 0x37) & 2) != 0) {
          *pfVar10 = FLOAT_803e52fc;
        }
        FUN_8000da58(iVar4,0x9b);
        fVar1 = *pfVar10 - FLOAT_803db414;
        *pfVar10 = fVar1;
        fVar2 = FLOAT_803e52fc;
        if (FLOAT_803e52fc < fVar1) {
          fVar1 = pfVar10[0xc] - FLOAT_803db414;
          pfVar10[0xc] = fVar1;
          if (fVar1 <= fVar2) {
            local_40 = FLOAT_803e532c;
            local_3c = FLOAT_803e5330;
            (**(code **)(*DAT_803dca88 + 8))(iVar4,0x51d,auStack76,2,0xffffffff,0);
            pfVar10[0xc] = FLOAT_803e5334;
          }
          *(byte *)(iVar4 + 0xaf) = *(byte *)(iVar4 + 0xaf) & 0xf7;
        }
        else {
          (**(code **)(*DAT_803dca78 + 0x14))(iVar4);
          *(undefined *)((int)pfVar10 + 0x36) = 0;
          FUN_8002b67c(iVar4);
        }
        break;
      case 10:
        FUN_80035f00(iVar4);
        *pfVar10 = *pfVar10 + FLOAT_803db414;
        local_30 = (double)CONCAT44(0x43300000,(int)*(short *)(pfVar10 + 0xd) ^ 0x80000000);
        if ((float)(local_30 - DOUBLE_803e5308) < *pfVar10) {
          FUN_801d1bfc(iVar4,pfVar10,1);
          *(undefined *)((int)pfVar10 + 0x36) = 1;
          FUN_8002b67c(iVar4);
        }
      }
      iVar5 = FUN_80036770(iVar4,auStack80,auStack84,auStack88,&local_40,&local_3c,local_38);
      local_40 = local_40 + FLOAT_803dcdd8;
      local_38[0] = local_38[0] + FLOAT_803dcddc;
      if ((iVar5 != 0) && ((*(byte *)((int)pfVar10 + 0x37) & 4) != 0)) {
        if (iVar5 == 0x10) {
          FUN_8002b050(iVar4,300);
        }
        else {
          if (*(char *)((int)pfVar10 + 0x36) != '\t') {
            FUN_8000bb18(iVar4,0x9d);
          }
          *(byte *)((int)pfVar10 + 0x37) = *(byte *)((int)pfVar10 + 0x37) & 0xfe;
          if (*(short *)(iVar9 + 0x1c) != -1) {
            FUN_800200e8((int)*(short *)(iVar9 + 0x1c),1);
          }
          *(undefined *)((int)pfVar10 + 0x36) = 9;
          *pfVar10 = FLOAT_803e52fc;
          uVar7 = FUN_800221a0(0,0x28);
          local_20 = (double)CONCAT44(0x43300000,uVar7 ^ 0x80000000);
          *(float *)(iVar4 + 0x98) = (float)(local_20 - DOUBLE_803e5308) / FLOAT_803e5340;
        }
        FUN_8009a1dc((double)FLOAT_803e5314,iVar4,auStack76,1,0);
      }
      if ((int)*(short *)(iVar4 + 0xa0) !=
          (int)*(short *)(&DAT_80326c78 + (uint)*(byte *)((int)pfVar10 + 0x36) * 2)) {
        FUN_80030334((double)FLOAT_803e52fc,iVar4,
                     (int)*(short *)(&DAT_80326c78 + (uint)*(byte *)((int)pfVar10 + 0x36) * 2),0);
      }
      iVar4 = FUN_8002fa48((double)*(float *)(&DAT_80326c90 +
                                             (uint)*(byte *)((int)pfVar10 + 0x36) * 4),
                           (double)FLOAT_803db414,iVar4,0);
      if (iVar4 == 0) {
        *(byte *)((int)pfVar10 + 0x37) = *(byte *)((int)pfVar10 + 0x37) & 0xfd;
      }
      else {
        *(byte *)((int)pfVar10 + 0x37) = *(byte *)((int)pfVar10 + 0x37) | 2;
      }
    }
  }
  else {
    iVar5 = FUN_80036770(iVar4,auStack80,auStack84,auStack88,&local_40,&local_3c,local_38);
    if ((iVar5 != 0) && (iVar5 != 0x10)) {
      local_40 = local_40 + FLOAT_803dcdd8;
      local_38[0] = local_38[0] + FLOAT_803dcddc;
      FUN_8009a1dc((double)FLOAT_803e5314,iVar4,auStack76,1,0);
      FUN_8000bb18(iVar4,0x47b);
      FUN_8002af98(iVar4);
    }
  }
  FUN_80286128();
  return;
}

