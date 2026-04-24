// Function: FUN_8014ffb4
// Entry: 8014ffb4
// Size: 1000 bytes

void FUN_8014ffb4(undefined4 param_1,undefined4 param_2,uint param_3)

{
  byte bVar1;
  float fVar2;
  float fVar3;
  int iVar4;
  undefined4 uVar5;
  uint uVar6;
  int iVar7;
  undefined *puVar8;
  float *pfVar9;
  undefined8 uVar10;
  
  uVar10 = FUN_802860dc();
  fVar3 = FLOAT_803e2740;
  uVar5 = (undefined4)((ulonglong)uVar10 >> 0x20);
  iVar7 = (int)uVar10;
  puVar8 = (&PTR_DAT_8031f174)[(uint)*(byte *)(iVar7 + 0x33b) * 10];
  if ((*(uint *)(iVar7 + 0x2dc) & 0x4000) == 0) {
    if ((*(float *)(iVar7 + 0x328) == FLOAT_803e2740) || (*(short *)(iVar7 + 0x338) == 0)) {
      bVar1 = *(byte *)(iVar7 + 0x2f1);
      uVar6 = bVar1 & 0x1f;
      if ((bVar1 & 0x10) != 0) {
        uVar6 = bVar1 & 0x17;
      }
      if (0x18 < uVar6) {
        uVar6 = 0;
      }
      fVar2 = FLOAT_803e2748;
      if ((bVar1 & 0x20) != 0) {
        uVar6 = 0;
        fVar2 = FLOAT_803e2744;
      }
      if (((param_3 & 0xff) != 0) &&
         ((((bVar1 != 0 || (*(float *)(iVar7 + 0x324) != FLOAT_803e2740)) &&
           ((*(uint *)(iVar7 + 0x2dc) & 0x40) == 0)) && ((bVar1 & 0x20) == 0)))) {
        if (*(float *)(iVar7 + 0x324) == FLOAT_803e2740) {
          iVar4 = (uint)*(byte *)(iVar7 + 0x33b) * 2;
          uVar6 = FUN_800221a0((&DAT_8031f25c)[iVar4],(&DAT_8031f25d)[iVar4]);
          *(float *)(iVar7 + 0x324) =
               *(float *)(iVar7 + 0x334) +
               (float)((double)CONCAT44(0x43300000,uVar6 ^ 0x80000000) - DOUBLE_803e2758);
          *(float *)(iVar7 + 0x334) = FLOAT_803e2740;
          uVar5 = 0;
          goto LAB_80150384;
        }
        *(float *)(iVar7 + 0x324) = *(float *)(iVar7 + 0x324) - FLOAT_803db414;
        if (fVar3 < *(float *)(iVar7 + 0x324)) {
          uVar5 = 0;
          goto LAB_80150384;
        }
        *(float *)(iVar7 + 0x324) = fVar3;
      }
      if ((((((param_3 & 0xff) == 0) || (*(char *)(iVar7 + 0x2f1) == '\0')) ||
           (puVar8[uVar6 * 0xc + 8] == '\0')) && ((*(byte *)(iVar7 + 0x2f1) & 0x20) == 0)) ||
         ((*(byte *)(iVar7 + 0x33c) == uVar6 && (FLOAT_803e2740 != *(float *)(iVar7 + 0x32c))))) {
        if (*(float *)(iVar7 + 0x32c) == FLOAT_803e2740) {
          uVar5 = 0;
        }
        else {
          FUN_8014cf7c((double)*(float *)(*(int *)(iVar7 + 0x29c) + 0xc),
                       (double)*(float *)(*(int *)(iVar7 + 0x29c) + 0x14),uVar5,iVar7,0xf,0);
          if (FLOAT_803e2750 < *(float *)(iVar7 + 0x308)) {
            *(float *)(iVar7 + 0x308) = *(float *)(iVar7 + 0x308) - FLOAT_803e2754;
          }
          if ((*(uint *)(iVar7 + 0x2dc) & 0x40000000) != 0) {
            iVar4 = (uint)*(byte *)(iVar7 + 0x33c) * 0xc;
            FUN_8014d08c((double)*(float *)(puVar8 + iVar4),uVar5,iVar7,puVar8[iVar4 + 8],0,
                         *(uint *)(puVar8 + iVar4 + 4) & 0xff);
            FUN_80030304((double)*(float *)(&DAT_8031dd30 +
                                           (uint)(byte)puVar8[(uint)*(byte *)(iVar7 + 0x33c) * 0xc +
                                                              8] * 4),uVar5);
          }
          *(float *)(iVar7 + 0x32c) = *(float *)(iVar7 + 0x32c) - FLOAT_803db414;
          if (FLOAT_803e2740 < *(float *)(iVar7 + 0x32c)) {
            uVar5 = 1;
          }
          else {
            *(float *)(iVar7 + 0x32c) = FLOAT_803e2740;
            *(uint *)(iVar7 + 0x2dc) = *(uint *)(iVar7 + 0x2dc) & 0xffffffbf;
            *(uint *)(iVar7 + 0x2dc) = *(uint *)(iVar7 + 0x2dc) | 0x40000000;
            *(byte *)(iVar7 + 0x2f2) = *(byte *)(iVar7 + 0x2f2) & 0x7f;
            *(undefined *)(iVar7 + 0x33c) = 0;
            uVar5 = 0;
          }
        }
      }
      else if (((*(uint *)(iVar7 + 0x2dc) & 0x800080) == 0) &&
              ((*(byte *)(iVar7 + 0x2f1) & 0x20) == 0)) {
        if ((*(uint *)(iVar7 + 0x2dc) & 0x40000000) != 0) {
          FUN_801513ac(uVar5,iVar7);
        }
        uVar5 = 0;
      }
      else {
        pfVar9 = (float *)(puVar8 + uVar6 * 0xc);
        fVar3 = FLOAT_803e274c * fVar2 * *pfVar9;
        *(float *)(iVar7 + 0x330) = fVar3;
        *(float *)(iVar7 + 0x32c) = fVar3;
        *(uint *)(iVar7 + 0x2dc) = *(uint *)(iVar7 + 0x2dc) | 0x40;
        *(byte *)(iVar7 + 0x2f2) = *(byte *)(iVar7 + 0x2f2) | 0x80;
        *(undefined *)(iVar7 + 0x2f3) = 0;
        *(undefined *)(iVar7 + 0x2f4) = 0;
        FUN_8014d08c((double)(fVar2 * *pfVar9),uVar5,iVar7,*(undefined *)(pfVar9 + 2),0,
                     (uint)pfVar9[1] & 0xff);
        FUN_80030304((double)*(float *)(&DAT_8031dd30 + (uint)*(byte *)(pfVar9 + 2) * 4),uVar5);
        *(char *)(iVar7 + 0x33c) = (char)uVar6;
        uVar5 = 1;
      }
    }
    else {
      uVar5 = 0;
    }
  }
  else {
    uVar5 = 0;
  }
LAB_80150384:
  FUN_80286128(uVar5);
  return;
}

