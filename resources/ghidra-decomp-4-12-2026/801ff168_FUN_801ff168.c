// Function: FUN_801ff168
// Entry: 801ff168
// Size: 3320 bytes

/* WARNING: Removing unreachable block (ram,0x801ff5b0) */

void FUN_801ff168(void)

{
  float fVar1;
  float fVar2;
  short *psVar3;
  int iVar4;
  int iVar5;
  char cVar7;
  uint uVar6;
  int in_r7;
  undefined4 in_r8;
  int in_r9;
  undefined4 in_r10;
  int iVar8;
  int iVar9;
  float *pfVar10;
  int iVar11;
  double dVar12;
  undefined8 uVar13;
  double dVar14;
  double dVar15;
  double in_f4;
  undefined8 in_f5;
  undefined8 in_f6;
  undefined8 in_f7;
  undefined8 in_f8;
  float local_58;
  undefined4 local_54;
  undefined4 local_50;
  float local_4c;
  float local_48;
  float local_44;
  float local_40;
  float local_3c;
  float local_38;
  undefined8 local_30;
  
  psVar3 = (short *)FUN_80286838();
  iVar11 = *(int *)(psVar3 + 0x26);
  iVar4 = FUN_8002bac4();
  pfVar10 = *(float **)(psVar3 + 0x5c);
  local_54 = DAT_803e6e58;
  local_50 = DAT_803e6e5c;
  dVar14 = (double)*(float *)(psVar3 + 8);
  dVar15 = (double)*(float *)(psVar3 + 10);
  iVar5 = FUN_8005b478((double)*(float *)(psVar3 + 6),dVar14);
  if (iVar5 != -1) {
    FUN_801fe7a4((int)psVar3);
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
        fVar2 = FLOAT_803e6e7c;
        *(float *)(psVar3 + 0x12) =
             *(float *)(psVar3 + 0x12) +
             (*(float *)(iVar11 + 8) - *(float *)(psVar3 + 6)) / FLOAT_803e6e7c;
        *(float *)(psVar3 + 0x14) =
             *(float *)(psVar3 + 0x14) + (*(float *)(iVar11 + 0xc) - *(float *)(psVar3 + 8)) / fVar2
        ;
        *(float *)(psVar3 + 0x16) =
             *(float *)(psVar3 + 0x16) +
             (*(float *)(iVar11 + 0x10) - *(float *)(psVar3 + 10)) / fVar2;
        uVar6 = FUN_80020078(0x44d);
        if (uVar6 != 0) {
          *(undefined *)(pfVar10 + 0x46) = 10;
        }
      }
      *(ushort *)(*(int *)(psVar3 + 0x2a) + 0x60) =
           *(ushort *)(*(int *)(psVar3 + 0x2a) + 0x60) | 0x400;
      local_40 = FLOAT_803e6e60;
      local_3c = FLOAT_803e6e60;
      local_38 = FLOAT_803e6e60;
      FUN_801fedac();
      *(float *)(psVar3 + 0x12) = *(float *)(psVar3 + 0x12) + local_40;
      *(float *)(psVar3 + 0x14) = *(float *)(psVar3 + 0x14) + local_3c;
      *(float *)(psVar3 + 0x16) = *(float *)(psVar3 + 0x16) + local_38;
      iVar5 = FUN_801feb98((double)(*(float *)(psVar3 + 0x12) * FLOAT_803dc074),
                           (double)(*(float *)(psVar3 + 0x16) * FLOAT_803dc074),(int)psVar3,
                           &local_58,1);
      fVar2 = FLOAT_803e6ecc;
      if (iVar5 != 0) {
        *(float *)(psVar3 + 0x12) = FLOAT_803e6ecc * *(float *)(psVar3 + 0x12);
        *(float *)(psVar3 + 0x16) = fVar2 * *(float *)(psVar3 + 0x16);
        FUN_801feb98((double)(*(float *)(psVar3 + 0x12) * FLOAT_803dc074),
                     (double)(*(float *)(psVar3 + 0x16) * FLOAT_803dc074),(int)psVar3,&local_58,1);
      }
      local_58 = local_58 + *pfVar10;
      if (FLOAT_803dc078 == FLOAT_803e6e60) {
        *(float *)(psVar3 + 0x14) = FLOAT_803e6e60;
      }
      else {
        *(float *)(psVar3 + 0x14) = local_58 * FLOAT_803e6ed0 * FLOAT_803dc078;
      }
      FUN_80022264(100,5000);
      FUN_80022264(100,5000);
      dVar14 = (double)(*(float *)(psVar3 + 0x14) * FLOAT_803dc074);
      dVar15 = (double)(*(float *)(psVar3 + 0x16) * FLOAT_803dc074);
      FUN_8002ba34((double)(*(float *)(psVar3 + 0x12) * FLOAT_803dc074),dVar14,dVar15,(int)psVar3);
      uVar6 = FUN_80022264(0,10);
      if ((uVar6 == 0) && (local_58 < FLOAT_803e6e98)) {
        uVar6 = FUN_80022264(1,10);
        local_30 = (double)CONCAT44(0x43300000,uVar6 ^ 0x80000000);
        in_f4 = (double)(float)(local_30 - DOUBLE_803e6ea8);
        dVar14 = (double)(*(float *)(psVar3 + 8) - *pfVar10);
        dVar15 = (double)*(float *)(psVar3 + 10);
        (**(code **)(*DAT_803dd718 + 0x14))((double)*(float *)(psVar3 + 6),(int)*psVar3,1);
      }
      uVar6 = FUN_80020078(0x426);
      if (uVar6 == 0) {
        if ((*(byte *)((int)pfVar10 + 0x119) & 2) != 0) {
          *(byte *)((int)psVar3 + 0xaf) = *(byte *)((int)psVar3 + 0xaf) | 8;
        }
      }
      else {
        *(byte *)((int)psVar3 + 0xaf) = *(byte *)((int)psVar3 + 0xaf) & 0xf7;
        dVar14 = (double)FLOAT_803e6ed4;
        *pfVar10 = -(float)(dVar14 * (double)FLOAT_803dc074 - (double)*pfVar10);
        if (*pfVar10 < FLOAT_803e6e84) {
          uVar6 = FUN_80020078(0x428);
          FUN_800201ac(0x428,uVar6 + 1);
          *(undefined *)(pfVar10 + 0x46) = 7;
          fVar2 = FLOAT_803e6e60;
          *(float *)(psVar3 + 0x14) = FLOAT_803e6e60;
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
      dVar14 = (double)FLOAT_803e6e60;
      iVar5 = FUN_801feb98(dVar14,dVar14,(int)psVar3,&local_58,1);
      if (iVar5 == 0) {
        *(undefined *)(pfVar10 + 0x46) = 2;
      }
      else {
        fVar2 = local_58;
        if (local_58 < FLOAT_803e6e60) {
          fVar2 = -local_58;
        }
        if (FLOAT_803e6eb8 <= fVar2) {
          *(float *)(psVar3 + 0x14) = *(float *)(psVar3 + 0x14) + FLOAT_803e6ebc;
          fVar2 = FLOAT_803e6e60;
          if (FLOAT_803e6e60 < local_58) {
            *(float *)(psVar3 + 0x14) = FLOAT_803e6ec0 * -*(float *)(psVar3 + 0x14);
            fVar1 = FLOAT_803e6ec4;
            *(float *)(psVar3 + 0x12) = *(float *)(psVar3 + 0x12) * FLOAT_803e6ec4;
            *(float *)(psVar3 + 0x16) = *(float *)(psVar3 + 0x16) * fVar1;
            fVar1 = *(float *)(psVar3 + 0x14);
            if (fVar1 < fVar2) {
              fVar1 = -fVar1;
            }
            if (FLOAT_803e6ec8 < fVar1) {
              FUN_8000bb38((uint)psVar3,0x2df);
            }
          }
          dVar14 = (double)(*(float *)(psVar3 + 0x14) * FLOAT_803dc074);
          dVar15 = (double)(*(float *)(psVar3 + 0x16) * FLOAT_803dc074);
          FUN_8002ba34((double)(*(float *)(psVar3 + 0x12) * FLOAT_803dc074),dVar14,dVar15,
                       (int)psVar3);
          *(byte *)((int)psVar3 + 0xaf) = *(byte *)((int)psVar3 + 0xaf) | 8;
        }
        else {
          if ((*(byte *)((int)pfVar10 + 0x119) & 0x10) == 0) {
            *(undefined *)(pfVar10 + 0x46) = 1;
          }
          else {
            *(undefined *)(pfVar10 + 0x46) = 0xd;
          }
          fVar2 = FLOAT_803e6e60;
          *(float *)(psVar3 + 0x12) = FLOAT_803e6e60;
          *(float *)(psVar3 + 0x16) = fVar2;
          *(float *)(psVar3 + 0x14) = fVar2;
          *(float *)(psVar3 + 8) = *(float *)(psVar3 + 8) + local_58;
        }
      }
      break;
    case 6:
      dVar12 = (double)FUN_80021754((float *)(psVar3 + 0xc),(float *)(iVar11 + 8));
      if ((dVar12 <= (double)FLOAT_803e6ed8) || ((*(byte *)((int)pfVar10 + 0x119) & 2) != 0)) {
        uVar6 = FUN_80014e9c(0);
        if ((uVar6 & 0x100) == 0) {
          *(ushort *)(*(int *)(psVar3 + 0x2a) + 0x60) =
               *(ushort *)(*(int *)(psVar3 + 0x2a) + 0x60) & 0xfffe;
          FUN_800379bc(dVar12,dVar14,dVar15,in_f4,in_f5,in_f6,in_f7,in_f8,iVar4,0x100008,
                       (uint)psVar3,0x38000,in_r7,in_r8,in_r9,in_r10);
          *(byte *)((int)psVar3 + 0xaf) = *(byte *)((int)psVar3 + 0xaf) | 8;
        }
        else {
          *(undefined *)(pfVar10 + 0x46) = 5;
          *(byte *)((int)psVar3 + 0xaf) = *(byte *)((int)psVar3 + 0xaf) & 0xf7;
        }
      }
      else {
        iVar5 = FUN_8002bac4();
        iVar8 = *(int *)(psVar3 + 0x5c);
        iVar9 = *(int *)(psVar3 + 0x26);
        FUN_8003709c((int)psVar3,0x24);
        *(undefined *)(iVar8 + 0x118) = 3;
        FUN_800201ac(0x3c4,1);
        FUN_800201ac(0x86d,1);
        *(byte *)((int)psVar3 + 0xaf) = *(byte *)((int)psVar3 + 0xaf) | 8;
        uVar13 = FUN_800201ac((int)*(short *)(iVar9 + 0x1c),1);
        *(undefined2 *)(iVar8 + 0x11c) = 0xffff;
        *(undefined2 *)(iVar8 + 0x11e) = 0;
        *(float *)(iVar8 + 0x120) = FLOAT_803e6e64;
        FUN_800379bc(uVar13,dVar14,dVar15,in_f4,in_f5,in_f6,in_f7,in_f8,iVar5,0x7000a,(uint)psVar3,
                     iVar8 + 0x11c,in_r7,in_r8,in_r9,in_r10);
        psVar3[0x7c] = 0;
        psVar3[0x7d] = 0;
      }
      break;
    case 7:
      dVar14 = (double)FLOAT_803e6e60;
      FUN_801feb98(dVar14,dVar14,(int)psVar3,&local_58,0);
      fVar2 = local_58;
      if (local_58 < FLOAT_803e6e60) {
        fVar2 = -local_58;
      }
      if (FLOAT_803e6eb8 <= fVar2) {
        *(float *)(psVar3 + 0x14) = *(float *)(psVar3 + 0x14) + FLOAT_803e6edc;
        if (FLOAT_803e6e60 < local_58) {
          *(float *)(psVar3 + 0x14) = FLOAT_803e6ee0 * -*(float *)(psVar3 + 0x14);
        }
        dVar14 = (double)(*(float *)(psVar3 + 0x14) * FLOAT_803dc074);
        dVar15 = (double)(*(float *)(psVar3 + 0x16) * FLOAT_803dc074);
        FUN_8002ba34((double)(*(float *)(psVar3 + 0x12) * FLOAT_803dc074),dVar14,dVar15,(int)psVar3)
        ;
      }
      else {
        *(undefined *)(pfVar10 + 0x46) = 8;
        fVar2 = FLOAT_803e6e60;
        *(float *)(psVar3 + 0x12) = FLOAT_803e6e60;
        *(float *)(psVar3 + 0x16) = fVar2;
      }
      break;
    case 8:
      uVar6 = FUN_80020078(0x42a);
      if (uVar6 == 0) {
        uVar6 = FUN_80022264(0,10);
        if (uVar6 == 0) {
          in_r7 = -1;
          in_r8 = 0;
          in_r9 = *DAT_803dd708;
          (**(code **)(in_r9 + 8))(psVar3,0x3be,0,0);
        }
      }
      else {
        FUN_801fe954(psVar3,pfVar10);
      }
      break;
    case 9:
      iVar5 = FUN_80010340((double)FLOAT_803e6ee8,pfVar10 + 1);
      if ((iVar5 == 0) && (pfVar10[5] == 0.0)) {
        *(float *)(psVar3 + 0x12) = pfVar10[0x1b] - *(float *)(psVar3 + 6);
        *(float *)(psVar3 + 0x14) = pfVar10[0x1c] - *(float *)(psVar3 + 8);
        *(float *)(psVar3 + 0x16) = pfVar10[0x1d] - *(float *)(psVar3 + 10);
        dVar12 = FUN_80293900((double)(*(float *)(psVar3 + 0x16) * *(float *)(psVar3 + 0x16) +
                                      *(float *)(psVar3 + 0x12) * *(float *)(psVar3 + 0x12) +
                                      *(float *)(psVar3 + 0x14) * *(float *)(psVar3 + 0x14)));
        dVar14 = (double)FLOAT_803e6eec;
        if ((double)(float)(dVar14 * (double)FLOAT_803dc074) < dVar12) {
          FUN_800228f0((float *)(psVar3 + 0x12));
          dVar14 = (double)FLOAT_803e6eec;
          *(float *)(psVar3 + 0x12) =
               *(float *)(psVar3 + 0x12) * (float)(dVar14 * (double)FLOAT_803dc074);
          *(float *)(psVar3 + 0x14) =
               *(float *)(psVar3 + 0x14) * (float)(dVar14 * (double)FLOAT_803dc074);
          *(float *)(psVar3 + 0x16) =
               *(float *)(psVar3 + 0x16) * (float)(dVar14 * (double)FLOAT_803dc074);
          FUN_80137cd0();
        }
        *(float *)(psVar3 + 6) = *(float *)(psVar3 + 6) + *(float *)(psVar3 + 0x12);
        *(float *)(psVar3 + 8) = *(float *)(psVar3 + 8) + *(float *)(psVar3 + 0x14);
        *(float *)(psVar3 + 10) = *(float *)(psVar3 + 10) + *(float *)(psVar3 + 0x16);
      }
      else {
        cVar7 = (**(code **)(*DAT_803dd71c + 0x90))(pfVar10 + 1);
        if (cVar7 != '\0') {
          *(undefined *)(pfVar10 + 0x46) = 5;
        }
      }
      break;
    case 10:
      in_r7 = *DAT_803dd71c;
      cVar7 = (**(code **)(in_r7 + 0x8c))((double)FLOAT_803e6ee4,pfVar10 + 1,psVar3,&local_54,2);
      if (cVar7 == '\0') {
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
      goto LAB_801ffe48;
    case 0xc:
      uVar6 = FUN_80020078((int)*(short *)(iVar11 + 0x24));
      if (uVar6 != 0) {
        FUN_800372f8((int)psVar3,0x24);
        *(undefined *)(pfVar10 + 0x46) = 5;
      }
      break;
    case 0xd:
      FUN_80035ff8((int)psVar3);
      dVar15 = (double)FLOAT_803e6ef0;
      *(float *)(psVar3 + 0x12) =
           *(float *)(psVar3 + 0x12) +
           (float)((double)(*(float *)(iVar11 + 8) - *(float *)(psVar3 + 6)) / dVar15);
      *(float *)(psVar3 + 0x14) =
           *(float *)(psVar3 + 0x14) +
           (float)((double)(*(float *)(iVar11 + 0xc) - *(float *)(psVar3 + 8)) / dVar15);
      *(float *)(psVar3 + 0x16) =
           *(float *)(psVar3 + 0x16) +
           (float)((double)(*(float *)(iVar11 + 0x10) - *(float *)(psVar3 + 10)) / dVar15);
      local_4c = *(float *)(psVar3 + 6) - *(float *)(iVar11 + 8);
      local_48 = *(float *)(psVar3 + 8) - *(float *)(iVar11 + 0xc);
      local_44 = *(float *)(psVar3 + 10) - *(float *)(iVar11 + 0x10);
      FUN_8000da78((uint)psVar3,0x442);
      dVar12 = (double)local_44;
      if (dVar12 < (double)FLOAT_803e6e60) {
        dVar12 = -dVar12;
      }
      dVar14 = (double)local_4c;
      if (dVar14 < (double)FLOAT_803e6e60) {
        dVar14 = -dVar14;
      }
      if (FLOAT_803e6ef4 <= (float)(dVar14 + dVar12)) {
        dVar15 = FUN_80247f54((float *)(psVar3 + 0x12));
        dVar14 = (double)FLOAT_803e6ef8;
        local_30 = (double)(longlong)(int)(dVar15 / dVar14);
        for (iVar5 = 0; iVar5 < (int)(dVar15 / dVar14); iVar5 = iVar5 + 1) {
          in_r7 = -1;
          in_r8 = 0;
          in_r9 = *DAT_803dd708;
          (**(code **)(in_r9 + 8))(psVar3,0x345,0,1);
        }
        dVar14 = (double)(*(float *)(psVar3 + 0x14) * FLOAT_803dc074);
        dVar15 = (double)(*(float *)(psVar3 + 0x16) * FLOAT_803dc074);
        FUN_8002ba34((double)(*(float *)(psVar3 + 0x12) * FLOAT_803dc074),dVar14,dVar15,(int)psVar3)
        ;
      }
      else {
        FUN_80036018((int)psVar3);
        *(undefined *)(pfVar10 + 0x46) = 1;
        *(undefined4 *)(psVar3 + 6) = *(undefined4 *)(iVar11 + 8);
        *(undefined4 *)(psVar3 + 8) = *(undefined4 *)(iVar11 + 0xc);
        *(undefined4 *)(psVar3 + 10) = *(undefined4 *)(iVar11 + 0x10);
      }
    }
    if ((*(byte *)((int)pfVar10 + 0x119) & 8) == 0) {
      if ((((*(byte *)((int)psVar3 + 0xaf) & 1) != 0) && (uVar6 = FUN_80020078(0x3c4), uVar6 == 0))
         && (dVar12 = (double)FUN_80021754((float *)(psVar3 + 0xc),(float *)(iVar4 + 0x18)),
            dVar12 < (double)FLOAT_803e6efc)) {
        if ((*(byte *)((int)pfVar10 + 0x119) & 1) == 0) {
          iVar4 = FUN_8002bac4();
          iVar11 = *(int *)(psVar3 + 0x5c);
          iVar5 = *(int *)(psVar3 + 0x26);
          FUN_8003709c((int)psVar3,0x24);
          *(undefined *)(iVar11 + 0x118) = 3;
          FUN_800201ac(0x3c4,1);
          FUN_800201ac(0x86d,1);
          *(byte *)((int)psVar3 + 0xaf) = *(byte *)((int)psVar3 + 0xaf) | 8;
          uVar13 = FUN_800201ac((int)*(short *)(iVar5 + 0x1c),1);
          *(undefined2 *)(iVar11 + 0x11c) = 0xffff;
          *(undefined2 *)(iVar11 + 0x11e) = 0;
          *(float *)(iVar11 + 0x120) = FLOAT_803e6e64;
          FUN_800379bc(uVar13,dVar14,dVar15,in_f4,in_f5,in_f6,in_f7,in_f8,iVar4,0x7000a,(uint)psVar3
                       ,iVar11 + 0x11c,in_r7,in_r8,in_r9,in_r10);
        }
        else {
          fVar2 = *(float *)(psVar3 + 8) - *(float *)(iVar4 + 0x10);
          if (fVar2 < FLOAT_803e6e60) {
            fVar2 = -fVar2;
          }
          if (fVar2 < FLOAT_803e6f00) {
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
      FUN_80035ff8((int)psVar3);
      uVar6 = FUN_80020078((int)*(short *)(iVar11 + 0x1c));
      if (uVar6 != 0) {
        *(byte *)((int)pfVar10 + 0x119) = *(byte *)((int)pfVar10 + 0x119) & 0xf6;
        *(byte *)((int)psVar3 + 0xaf) = *(byte *)((int)psVar3 + 0xaf) & 0xf7;
        FUN_80036018((int)psVar3);
      }
    }
  }
LAB_801ffe48:
  FUN_80286884();
  return;
}

