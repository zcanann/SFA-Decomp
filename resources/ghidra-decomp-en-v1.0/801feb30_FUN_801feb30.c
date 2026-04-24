// Function: FUN_801feb30
// Entry: 801feb30
// Size: 3320 bytes

/* WARNING: Removing unreachable block (ram,0x801fef78) */

void FUN_801feb30(void)

{
  float fVar1;
  float fVar2;
  short *psVar3;
  int iVar4;
  int iVar5;
  uint uVar6;
  char cVar8;
  undefined4 uVar7;
  int iVar9;
  float *pfVar10;
  int iVar11;
  double dVar12;
  double dVar13;
  float local_58;
  undefined4 local_54;
  undefined4 local_50;
  float local_4c;
  float local_48;
  float local_44;
  float local_40;
  float local_3c;
  float local_38;
  double local_30;
  
  psVar3 = (short *)FUN_802860d4();
  iVar11 = *(int *)(psVar3 + 0x26);
  iVar4 = FUN_8002b9ec();
  pfVar10 = *(float **)(psVar3 + 0x5c);
  local_54 = DAT_803e61c0;
  local_50 = DAT_803e61c4;
  iVar5 = FUN_8005b2fc((double)*(float *)(psVar3 + 6),(double)*(float *)(psVar3 + 8),
                       (double)*(float *)(psVar3 + 10));
  if (iVar5 != -1) {
    FUN_801fe16c(psVar3);
    *(ushort *)(*(int *)(psVar3 + 0x2a) + 0x60) =
         *(ushort *)(*(int *)(psVar3 + 0x2a) + 0x60) & 0xfbff;
    switch(*(undefined *)(pfVar10 + 0x46)) {
    case 1:
      if (*(int *)(psVar3 + 0x7c) == 0) {
        *(ushort *)(*(int *)(psVar3 + 0x2a) + 0x60) =
             *(ushort *)(*(int *)(psVar3 + 0x2a) + 0x60) | 1;
      }
      *(byte *)((int)psVar3 + 0xaf) = *(byte *)((int)psVar3 + 0xaf) & 0xf7;
      break;
    case 2:
      if ((*(byte *)((int)pfVar10 + 0x119) & 4) != 0) {
        *(byte *)((int)psVar3 + 0xaf) = *(byte *)((int)psVar3 + 0xaf) | 8;
        fVar2 = FLOAT_803e61e4;
        *(float *)(psVar3 + 0x12) =
             *(float *)(psVar3 + 0x12) +
             (*(float *)(iVar11 + 8) - *(float *)(psVar3 + 6)) / FLOAT_803e61e4;
        *(float *)(psVar3 + 0x14) =
             *(float *)(psVar3 + 0x14) + (*(float *)(iVar11 + 0xc) - *(float *)(psVar3 + 8)) / fVar2
        ;
        *(float *)(psVar3 + 0x16) =
             *(float *)(psVar3 + 0x16) +
             (*(float *)(iVar11 + 0x10) - *(float *)(psVar3 + 10)) / fVar2;
        iVar5 = FUN_8001ffb4(0x44d);
        if (iVar5 != 0) {
          *(undefined *)(pfVar10 + 0x46) = 10;
        }
      }
      *(ushort *)(*(int *)(psVar3 + 0x2a) + 0x60) =
           *(ushort *)(*(int *)(psVar3 + 0x2a) + 0x60) | 0x400;
      local_40 = FLOAT_803e61c8;
      local_3c = FLOAT_803e61c8;
      local_38 = FLOAT_803e61c8;
      FUN_801fe774(psVar3,&local_40);
      *(float *)(psVar3 + 0x12) = *(float *)(psVar3 + 0x12) + local_40;
      *(float *)(psVar3 + 0x14) = *(float *)(psVar3 + 0x14) + local_3c;
      *(float *)(psVar3 + 0x16) = *(float *)(psVar3 + 0x16) + local_38;
      iVar5 = FUN_801fe560((double)(*(float *)(psVar3 + 0x12) * FLOAT_803db414),
                           (double)(*(float *)(psVar3 + 0x16) * FLOAT_803db414),psVar3,&local_58,1);
      fVar2 = FLOAT_803e6234;
      if (iVar5 != 0) {
        *(float *)(psVar3 + 0x12) = FLOAT_803e6234 * *(float *)(psVar3 + 0x12);
        *(float *)(psVar3 + 0x16) = fVar2 * *(float *)(psVar3 + 0x16);
        FUN_801fe560((double)(*(float *)(psVar3 + 0x12) * FLOAT_803db414),
                     (double)(*(float *)(psVar3 + 0x16) * FLOAT_803db414),psVar3,&local_58,1);
      }
      local_58 = local_58 + *pfVar10;
      if (FLOAT_803db418 == FLOAT_803e61c8) {
        *(float *)(psVar3 + 0x14) = FLOAT_803e61c8;
      }
      else {
        *(float *)(psVar3 + 0x14) = local_58 * FLOAT_803e6238 * FLOAT_803db418;
      }
      FUN_800221a0(100,5000);
      FUN_800221a0(100,5000);
      FUN_8002b95c((double)(*(float *)(psVar3 + 0x12) * FLOAT_803db414),
                   (double)(*(float *)(psVar3 + 0x14) * FLOAT_803db414),
                   (double)(*(float *)(psVar3 + 0x16) * FLOAT_803db414),psVar3);
      iVar5 = FUN_800221a0(0,10);
      if ((iVar5 == 0) && (local_58 < FLOAT_803e6200)) {
        uVar6 = FUN_800221a0(1,10);
        local_30 = (double)CONCAT44(0x43300000,uVar6 ^ 0x80000000);
        (**(code **)(*DAT_803dca98 + 0x14))
                  ((double)*(float *)(psVar3 + 6),(double)(*(float *)(psVar3 + 8) - *pfVar10),
                   (double)*(float *)(psVar3 + 10),(double)(float)(local_30 - DOUBLE_803e6210),
                   (int)*psVar3,1);
      }
      iVar5 = FUN_8001ffb4(0x426);
      if (iVar5 == 0) {
        if ((*(byte *)((int)pfVar10 + 0x119) & 2) != 0) {
          *(byte *)((int)psVar3 + 0xaf) = *(byte *)((int)psVar3 + 0xaf) | 8;
        }
      }
      else {
        *(byte *)((int)psVar3 + 0xaf) = *(byte *)((int)psVar3 + 0xaf) & 0xf7;
        *pfVar10 = -(FLOAT_803e623c * FLOAT_803db414 - *pfVar10);
        if (*pfVar10 < FLOAT_803e61ec) {
          iVar5 = FUN_8001ffb4(0x428);
          FUN_800200e8(0x428,iVar5 + 1);
          *(undefined *)(pfVar10 + 0x46) = 7;
          fVar2 = FLOAT_803e61c8;
          *(float *)(psVar3 + 0x14) = FLOAT_803e61c8;
          *(float *)(psVar3 + 0x12) = fVar2;
          *(float *)(psVar3 + 0x16) = fVar2;
          *(byte *)((int)psVar3 + 0xaf) = *(byte *)((int)psVar3 + 0xaf) | 8;
        }
      }
      break;
    case 4:
      *(byte *)((int)psVar3 + 0xaf) = *(byte *)((int)psVar3 + 0xaf) | 8;
      break;
    case 5:
      if (*(int *)(psVar3 + 0x7c) == 0) {
        *(ushort *)(*(int *)(psVar3 + 0x2a) + 0x60) =
             *(ushort *)(*(int *)(psVar3 + 0x2a) + 0x60) | 1;
      }
      iVar5 = FUN_801fe560((double)FLOAT_803e61c8,(double)FLOAT_803e61c8,psVar3,&local_58,1);
      if (iVar5 == 0) {
        *(undefined *)(pfVar10 + 0x46) = 2;
      }
      else {
        fVar2 = local_58;
        if (local_58 < FLOAT_803e61c8) {
          fVar2 = -local_58;
        }
        if (FLOAT_803e6220 <= fVar2) {
          *(float *)(psVar3 + 0x14) = *(float *)(psVar3 + 0x14) + FLOAT_803e6224;
          fVar2 = FLOAT_803e61c8;
          if (FLOAT_803e61c8 < local_58) {
            *(float *)(psVar3 + 0x14) = FLOAT_803e6228 * -*(float *)(psVar3 + 0x14);
            fVar1 = FLOAT_803e622c;
            *(float *)(psVar3 + 0x12) = *(float *)(psVar3 + 0x12) * FLOAT_803e622c;
            *(float *)(psVar3 + 0x16) = *(float *)(psVar3 + 0x16) * fVar1;
            fVar1 = *(float *)(psVar3 + 0x14);
            if (fVar1 < fVar2) {
              fVar1 = -fVar1;
            }
            if (FLOAT_803e6230 < fVar1) {
              FUN_8000bb18(psVar3,0x2df);
            }
          }
          FUN_8002b95c((double)(*(float *)(psVar3 + 0x12) * FLOAT_803db414),
                       (double)(*(float *)(psVar3 + 0x14) * FLOAT_803db414),
                       (double)(*(float *)(psVar3 + 0x16) * FLOAT_803db414),psVar3);
          *(byte *)((int)psVar3 + 0xaf) = *(byte *)((int)psVar3 + 0xaf) | 8;
        }
        else {
          if ((*(byte *)((int)pfVar10 + 0x119) & 0x10) == 0) {
            *(undefined *)(pfVar10 + 0x46) = 1;
          }
          else {
            *(undefined *)(pfVar10 + 0x46) = 0xd;
          }
          fVar2 = FLOAT_803e61c8;
          *(float *)(psVar3 + 0x12) = FLOAT_803e61c8;
          *(float *)(psVar3 + 0x16) = fVar2;
          *(float *)(psVar3 + 0x14) = fVar2;
          *(float *)(psVar3 + 8) = *(float *)(psVar3 + 8) + local_58;
        }
      }
      break;
    case 6:
      dVar13 = (double)FUN_80021690(psVar3 + 0xc,iVar11 + 8);
      if ((dVar13 <= (double)FLOAT_803e6240) || ((*(byte *)((int)pfVar10 + 0x119) & 2) != 0)) {
        uVar6 = FUN_80014e70(0);
        if ((uVar6 & 0x100) == 0) {
          *(ushort *)(*(int *)(psVar3 + 0x2a) + 0x60) =
               *(ushort *)(*(int *)(psVar3 + 0x2a) + 0x60) & 0xfffe;
          FUN_800378c4(iVar4,0x100008,psVar3,0x38000);
          *(byte *)((int)psVar3 + 0xaf) = *(byte *)((int)psVar3 + 0xaf) | 8;
        }
        else {
          *(undefined *)(pfVar10 + 0x46) = 5;
          *(byte *)((int)psVar3 + 0xaf) = *(byte *)((int)psVar3 + 0xaf) & 0xf7;
        }
      }
      else {
        uVar7 = FUN_8002b9ec();
        iVar5 = *(int *)(psVar3 + 0x5c);
        iVar9 = *(int *)(psVar3 + 0x26);
        FUN_80036fa4(psVar3,0x24);
        *(undefined *)(iVar5 + 0x118) = 3;
        FUN_800200e8(0x3c4,1);
        FUN_800200e8(0x86d,1);
        *(byte *)((int)psVar3 + 0xaf) = *(byte *)((int)psVar3 + 0xaf) | 8;
        FUN_800200e8((int)*(short *)(iVar9 + 0x1c),1);
        *(undefined2 *)(iVar5 + 0x11c) = 0xffff;
        *(undefined2 *)(iVar5 + 0x11e) = 0;
        *(float *)(iVar5 + 0x120) = FLOAT_803e61cc;
        FUN_800378c4(uVar7,0x7000a,psVar3,iVar5 + 0x11c);
        *(undefined4 *)(psVar3 + 0x7c) = 0;
      }
      break;
    case 7:
      FUN_801fe560((double)FLOAT_803e61c8,(double)FLOAT_803e61c8,psVar3,&local_58,0);
      fVar2 = local_58;
      if (local_58 < FLOAT_803e61c8) {
        fVar2 = -local_58;
      }
      if (FLOAT_803e6220 <= fVar2) {
        *(float *)(psVar3 + 0x14) = *(float *)(psVar3 + 0x14) + FLOAT_803e6244;
        if (FLOAT_803e61c8 < local_58) {
          *(float *)(psVar3 + 0x14) = FLOAT_803e6248 * -*(float *)(psVar3 + 0x14);
        }
        FUN_8002b95c((double)(*(float *)(psVar3 + 0x12) * FLOAT_803db414),
                     (double)(*(float *)(psVar3 + 0x14) * FLOAT_803db414),
                     (double)(*(float *)(psVar3 + 0x16) * FLOAT_803db414),psVar3);
      }
      else {
        *(undefined *)(pfVar10 + 0x46) = 8;
        fVar2 = FLOAT_803e61c8;
        *(float *)(psVar3 + 0x12) = FLOAT_803e61c8;
        *(float *)(psVar3 + 0x16) = fVar2;
      }
      break;
    case 8:
      iVar5 = FUN_8001ffb4(0x42a);
      if (iVar5 == 0) {
        iVar5 = FUN_800221a0(0,10);
        if (iVar5 == 0) {
          (**(code **)(*DAT_803dca88 + 8))(psVar3,0x3be,0,0,0xffffffff,0);
        }
      }
      else {
        FUN_801fe31c(psVar3,pfVar10);
      }
      break;
    case 9:
      iVar5 = FUN_80010320((double)FLOAT_803e6250,pfVar10 + 1);
      if ((iVar5 == 0) && (pfVar10[5] == 0.0)) {
        *(float *)(psVar3 + 0x12) = pfVar10[0x1b] - *(float *)(psVar3 + 6);
        *(float *)(psVar3 + 0x14) = pfVar10[0x1c] - *(float *)(psVar3 + 8);
        *(float *)(psVar3 + 0x16) = pfVar10[0x1d] - *(float *)(psVar3 + 10);
        dVar13 = (double)FUN_802931a0((double)(*(float *)(psVar3 + 0x16) * *(float *)(psVar3 + 0x16)
                                              + *(float *)(psVar3 + 0x12) *
                                                *(float *)(psVar3 + 0x12) +
                                                *(float *)(psVar3 + 0x14) *
                                                *(float *)(psVar3 + 0x14)));
        if ((double)(FLOAT_803e6254 * FLOAT_803db414) < dVar13) {
          FUN_8002282c(psVar3 + 0x12);
          fVar2 = FLOAT_803e6254;
          *(float *)(psVar3 + 0x12) = *(float *)(psVar3 + 0x12) * FLOAT_803e6254 * FLOAT_803db414;
          *(float *)(psVar3 + 0x14) = *(float *)(psVar3 + 0x14) * fVar2 * FLOAT_803db414;
          *(float *)(psVar3 + 0x16) = *(float *)(psVar3 + 0x16) * fVar2 * FLOAT_803db414;
          FUN_80137948(s__GREATER_803292f8);
        }
        *(float *)(psVar3 + 6) = *(float *)(psVar3 + 6) + *(float *)(psVar3 + 0x12);
        *(float *)(psVar3 + 8) = *(float *)(psVar3 + 8) + *(float *)(psVar3 + 0x14);
        *(float *)(psVar3 + 10) = *(float *)(psVar3 + 10) + *(float *)(psVar3 + 0x16);
      }
      else {
        cVar8 = (**(code **)(*DAT_803dca9c + 0x90))(pfVar10 + 1);
        if (cVar8 != '\0') {
          *(undefined *)(pfVar10 + 0x46) = 5;
        }
      }
      break;
    case 10:
      cVar8 = (**(code **)(*DAT_803dca9c + 0x8c))
                        ((double)FLOAT_803e624c,pfVar10 + 1,psVar3,&local_54,2);
      if (cVar8 == '\0') {
        *(byte *)((int)psVar3 + 0xaf) = *(byte *)((int)psVar3 + 0xaf) & 0xf7;
        *(undefined *)(pfVar10 + 0x46) = 9;
        if ((*(byte *)((int)pfVar10 + 0x119) & 4) != 0) {
          *(byte *)((int)pfVar10 + 0x119) = *(byte *)((int)pfVar10 + 0x119) & 0xfb;
        }
      }
      else {
        *(undefined *)(pfVar10 + 0x46) = 5;
      }
      break;
    case 0xb:
      *(byte *)((int)psVar3 + 0xaf) = *(byte *)((int)psVar3 + 0xaf) | 8;
      goto LAB_801ff810;
    case 0xc:
      iVar5 = FUN_8001ffb4((int)*(short *)(iVar11 + 0x24));
      if (iVar5 != 0) {
        FUN_80037200(psVar3,0x24);
        *(undefined *)(pfVar10 + 0x46) = 5;
      }
      break;
    case 0xd:
      FUN_80035f00(psVar3);
      fVar2 = FLOAT_803e6258;
      *(float *)(psVar3 + 0x12) =
           *(float *)(psVar3 + 0x12) +
           (*(float *)(iVar11 + 8) - *(float *)(psVar3 + 6)) / FLOAT_803e6258;
      *(float *)(psVar3 + 0x14) =
           *(float *)(psVar3 + 0x14) + (*(float *)(iVar11 + 0xc) - *(float *)(psVar3 + 8)) / fVar2;
      *(float *)(psVar3 + 0x16) =
           *(float *)(psVar3 + 0x16) + (*(float *)(iVar11 + 0x10) - *(float *)(psVar3 + 10)) / fVar2
      ;
      local_4c = *(float *)(psVar3 + 6) - *(float *)(iVar11 + 8);
      local_48 = *(float *)(psVar3 + 8) - *(float *)(iVar11 + 0xc);
      local_44 = *(float *)(psVar3 + 10) - *(float *)(iVar11 + 0x10);
      FUN_8000da58(psVar3,0x442);
      fVar2 = local_44;
      if (local_44 < FLOAT_803e61c8) {
        fVar2 = -local_44;
      }
      fVar1 = local_4c;
      if (local_4c < FLOAT_803e61c8) {
        fVar1 = -local_4c;
      }
      if (FLOAT_803e625c <= fVar1 + fVar2) {
        dVar12 = (double)FUN_802477f0(psVar3 + 0x12);
        dVar13 = (double)FLOAT_803e6260;
        local_30 = (double)(longlong)(int)(dVar12 / dVar13);
        for (iVar5 = 0; iVar5 < (int)(dVar12 / dVar13); iVar5 = iVar5 + 1) {
          (**(code **)(*DAT_803dca88 + 8))(psVar3,0x345,0,1,0xffffffff,0);
        }
        FUN_8002b95c((double)(*(float *)(psVar3 + 0x12) * FLOAT_803db414),
                     (double)(*(float *)(psVar3 + 0x14) * FLOAT_803db414),
                     (double)(*(float *)(psVar3 + 0x16) * FLOAT_803db414),psVar3);
      }
      else {
        FUN_80035f20(psVar3);
        *(undefined *)(pfVar10 + 0x46) = 1;
        *(undefined4 *)(psVar3 + 6) = *(undefined4 *)(iVar11 + 8);
        *(undefined4 *)(psVar3 + 8) = *(undefined4 *)(iVar11 + 0xc);
        *(undefined4 *)(psVar3 + 10) = *(undefined4 *)(iVar11 + 0x10);
      }
    }
    if ((*(byte *)((int)pfVar10 + 0x119) & 8) == 0) {
      if ((((*(byte *)((int)psVar3 + 0xaf) & 1) != 0) && (iVar5 = FUN_8001ffb4(0x3c4), iVar5 == 0))
         && (dVar13 = (double)FUN_80021690(psVar3 + 0xc,iVar4 + 0x18),
            dVar13 < (double)FLOAT_803e6264)) {
        if ((*(byte *)((int)pfVar10 + 0x119) & 1) == 0) {
          uVar7 = FUN_8002b9ec();
          iVar5 = *(int *)(psVar3 + 0x5c);
          iVar4 = *(int *)(psVar3 + 0x26);
          FUN_80036fa4(psVar3,0x24);
          *(undefined *)(iVar5 + 0x118) = 3;
          FUN_800200e8(0x3c4,1);
          FUN_800200e8(0x86d,1);
          *(byte *)((int)psVar3 + 0xaf) = *(byte *)((int)psVar3 + 0xaf) | 8;
          FUN_800200e8((int)*(short *)(iVar4 + 0x1c),1);
          *(undefined2 *)(iVar5 + 0x11c) = 0xffff;
          *(undefined2 *)(iVar5 + 0x11e) = 0;
          *(float *)(iVar5 + 0x120) = FLOAT_803e61cc;
          FUN_800378c4(uVar7,0x7000a,psVar3,iVar5 + 0x11c);
        }
        else {
          fVar2 = *(float *)(psVar3 + 8) - *(float *)(iVar4 + 0x10);
          if (fVar2 < FLOAT_803e61c8) {
            fVar2 = -fVar2;
          }
          if (fVar2 < FLOAT_803e6268) {
            *(byte *)((int)psVar3 + 0xaf) = *(byte *)((int)psVar3 + 0xaf) | 8;
            *(undefined *)(pfVar10 + 0x46) = 6;
            *(ushort *)(*(int *)(psVar3 + 0x2a) + 0x60) =
                 *(ushort *)(*(int *)(psVar3 + 0x2a) + 0x60) & 0xfffe;
          }
        }
      }
    }
    else {
      *(byte *)((int)psVar3 + 0xaf) = *(byte *)((int)psVar3 + 0xaf) | 8;
      FUN_80035f00(psVar3);
      iVar4 = FUN_8001ffb4((int)*(short *)(iVar11 + 0x1c));
      if (iVar4 != 0) {
        *(byte *)((int)pfVar10 + 0x119) = *(byte *)((int)pfVar10 + 0x119) & 0xf6;
        *(byte *)((int)psVar3 + 0xaf) = *(byte *)((int)psVar3 + 0xaf) & 0xf7;
        FUN_80035f20(psVar3);
      }
    }
  }
LAB_801ff810:
  FUN_80286120();
  return;
}

