// Function: FUN_8009251c
// Entry: 8009251c
// Size: 2376 bytes

/* WARNING: Removing unreachable block (ram,0x80092e44) */

void FUN_8009251c(void)

{
  short *psVar1;
  short sVar4;
  uint uVar2;
  undefined4 uVar3;
  int *piVar5;
  int iVar6;
  char cVar7;
  int *piVar8;
  int iVar9;
  int **ppiVar10;
  undefined4 uVar11;
  double dVar12;
  undefined8 in_f31;
  double dVar13;
  float local_d8;
  float local_d4;
  float local_d0;
  float local_cc;
  float local_c8;
  float local_c4;
  float local_c0;
  float local_bc;
  float local_b8;
  float local_b4 [2];
  float local_ac;
  float local_a8;
  float local_a4;
  float local_a0;
  short local_9c;
  undefined2 local_9a;
  undefined2 local_98;
  float local_94;
  float local_90;
  float local_8c;
  float local_88;
  undefined auStack132 [52];
  double local_50;
  double local_48;
  undefined auStack8 [8];
  
  uVar11 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  FUN_802860cc();
  iVar9 = 0;
  iVar6 = 0;
  psVar1 = (short *)FUN_8000faac();
  cVar7 = '\0';
  piVar8 = (int *)0x0;
  dVar13 = (double)FLOAT_803df248;
  if (DAT_803dd1c0 == '\0') {
    DAT_803dd1c8 = FUN_80054d54(0x16a);
    DAT_8039a818 = FUN_80054d54(0x5da);
    DAT_8039a81c = FUN_80054d54(0x63f);
    DAT_8039a820 = FUN_80054d54(0x640);
    DAT_8039a824 = FUN_80054d54(0x641);
    DAT_803dd1c4 = FUN_80054d54(0x151);
    DAT_803dd1c0 = '\x01';
  }
  sVar4 = FUN_80008b4c(0xffffffff);
  if (sVar4 != 1) {
    DAT_803dd1cc = DAT_803dd19b;
    DAT_803dd19b = '\0';
    while (iVar9 < 8) {
      ppiVar10 = (int **)((int)&DAT_8039a828 + iVar6);
      piVar5 = *ppiVar10;
      if ((piVar5 == (int *)0x0) || ((*piVar5 != 0 && ((*(ushort *)(*piVar5 + 0xb0) & 0x40) == 0))))
      {
        if ((piVar5 == (int *)0x0) || (piVar5[0x500] == 0)) {
          if ((piVar5 != (int *)0x0) && (*(char *)((int)piVar5 + 0x144f) == '\0')) {
            if (piVar5[0x4fd] == 4) {
              DAT_803dd19b = '\x01';
            }
            if (piVar5[0x4fe] == 0) {
              if ((int)(float)piVar5[0x50d] < piVar5[0x4ff]) {
                local_50 = (double)CONCAT44(0x43300000,(uint)DAT_803db410);
                piVar5[0x50d] =
                     (int)((float)(local_50 - DOUBLE_803df1b0) * (float)piVar5[0x50b] +
                          (float)piVar5[0x50d]);
              }
            }
            else {
              local_50 = (double)CONCAT44(0x43300000,(uint)DAT_803db410);
              piVar5[0x50d] =
                   (int)((float)(local_50 - DOUBLE_803df1b0) * (float)piVar5[0x50c] +
                        (float)piVar5[0x50d]);
              if ((float)(*ppiVar10)[0x50d] <= FLOAT_803df1a0) {
                *(undefined *)((int)*ppiVar10 + 0x144f) = 1;
              }
            }
            piVar5 = *ppiVar10;
            local_50 = (double)(longlong)(int)(float)piVar5[0x50d];
            if (piVar5[0x4ff] < (int)(float)piVar5[0x50d]) {
              local_50 = (double)CONCAT44(0x43300000,piVar5[0x4ff] ^ 0x80000000);
              piVar5[0x50d] = (int)(float)(local_50 - DOUBLE_803df1a8);
            }
            if ((float)(*ppiVar10)[0x50d] < FLOAT_803df1a0) {
              (*ppiVar10)[0x50d] = (int)FLOAT_803df1a0;
            }
            if (**ppiVar10 != 0) {
              FUN_8000e10c(**ppiVar10,&local_c0,&local_bc,&local_b8);
            }
            if ((*(char *)((int)*ppiVar10 + 0x1452) != '\0') && (psVar1 != (short *)0x0)) {
              if ((*ppiVar10)[0x4fd] == 4) {
                local_cc = FLOAT_803df1a0;
                local_c8 = FLOAT_803df1a0;
                local_c4 = FLOAT_803df1fc;
                local_90 = FLOAT_803df1a0;
                local_8c = FLOAT_803df1a0;
                local_88 = FLOAT_803df1a0;
                local_94 = FLOAT_803df1a4;
                local_98 = 0;
                local_9a = 0;
                local_9c = -1 - *psVar1;
                FUN_80021ac8(&local_9c,&local_cc);
                local_c0 = *(float *)(psVar1 + 0x22) + local_cc;
                local_bc = (*(float *)(psVar1 + 0x24) - FLOAT_803df24c) + local_c8;
                local_b8 = *(float *)(psVar1 + 0x26) + local_c4;
              }
              else {
                local_c0 = *(float *)(psVar1 + 0x22);
                local_bc = *(float *)(psVar1 + 0x24) - FLOAT_803df24c;
                local_b8 = *(float *)(psVar1 + 0x26);
              }
            }
            piVar5 = *ppiVar10;
            local_50 = (double)CONCAT44(0x43300000,(uint)DAT_803db410);
            piVar5[0x510] =
                 (int)((float)(local_50 - DOUBLE_803df1b0) * (float)piVar5[0x511] +
                      (float)piVar5[0x510]);
            piVar5 = *ppiVar10;
            if (FLOAT_803df1a0 != (float)piVar5[0x50e]) {
              if ((float)piVar5[0x510] <= (float)piVar5[0x50f]) {
                if ((float)piVar5[0x510] < FLOAT_803df1a0) {
                  piVar5[0x511] = (int)((float)piVar5[0x511] * FLOAT_803df244);
                  local_50 = (double)(longlong)(int)(FLOAT_803df1c8 * (float)(*ppiVar10)[0x50e]);
                  uVar2 = FUN_800221a0(1,(int)(FLOAT_803df1c8 * (float)(*ppiVar10)[0x50e]));
                  local_48 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
                  (*ppiVar10)[0x50f] = (int)(float)(local_48 - DOUBLE_803df1a8);
                  (*ppiVar10)[0x510] = (int)FLOAT_803df1a0;
                }
              }
              else {
                piVar5[0x511] = (int)((float)piVar5[0x511] * FLOAT_803df244);
                (*ppiVar10)[0x510] = (*ppiVar10)[0x50f];
              }
            }
            piVar5 = *ppiVar10;
            if (*(char *)((int)piVar5 + 0x144d) == '\0') {
              local_a8 = local_c0;
              local_a4 = local_bc;
              local_a0 = local_b8;
              FUN_800916c0((double)(float)piVar5[0x50e],local_b4,&local_a8);
              piVar5 = *ppiVar10;
              if (piVar5[0x4fd] == 0) {
                piVar5[0x508] = (int)-local_b4[0];
                (*ppiVar10)[0x509] = (int)-local_ac;
              }
              else {
                piVar5[0x508] = (int)-(local_b4[0] + (float)piVar5[0x510]);
                (*ppiVar10)[0x509] = (int)-(local_ac + (float)(*ppiVar10)[0x510]);
                (*ppiVar10)[0x50a] = (int)FLOAT_803df1a0;
              }
              (*ppiVar10)[0x503] = (int)local_c0;
              (*ppiVar10)[0x504] = (int)local_bc;
              (*ppiVar10)[0x505] = (int)local_b8;
            }
            else {
              local_a8 = (float)piVar5[0x503];
              local_a4 = (float)piVar5[0x504];
              local_a0 = (float)piVar5[0x505];
              FUN_800916c0((double)(float)piVar5[0x50e],local_b4,&local_a8);
              (*ppiVar10)[0x508] = (int)(-local_b4[0] + (float)(*ppiVar10)[0x510]);
              (*ppiVar10)[0x509] = (int)(-local_ac + (float)(*ppiVar10)[0x510]);
              (*ppiVar10)[0x50a] = (int)FLOAT_803df1a0;
            }
            piVar5 = *ppiVar10;
            if (*(char *)((int)piVar5 + 0x1453) == '\0') {
              piVar5[0x4f9] = (int)local_c0;
              (*ppiVar10)[0x4fa] = (int)local_bc;
              (*ppiVar10)[0x4fb] = (int)local_b8;
              *(undefined *)((int)*ppiVar10 + 0x1453) = 1;
            }
            else {
              piVar5[0x4f9] = piVar5[0x4f6];
              (*ppiVar10)[0x4fa] = (*ppiVar10)[0x4f7];
              (*ppiVar10)[0x4fb] = (*ppiVar10)[0x4f8];
            }
            (*ppiVar10)[0x4f6] = (int)local_c0;
            (*ppiVar10)[0x4f7] = (int)local_bc;
            (*ppiVar10)[0x4f8] = (int)local_b8;
            FUN_80090f88((*ppiVar10)[0x4fc]);
            piVar5 = *ppiVar10;
            if (FLOAT_803df1a0 < (float)piVar5[0x50d]) {
              local_d8 = (float)piVar5[0x503] - *(float *)(psVar1 + 6);
              local_d4 = (float)piVar5[0x504] - *(float *)(psVar1 + 8);
              local_d0 = (float)piVar5[0x505] - *(float *)(psVar1 + 10);
              dVar12 = (double)FUN_802477f0(&local_d8);
              if (dVar12 < dVar13) {
                piVar8 = *ppiVar10;
                dVar13 = dVar12;
              }
            }
          }
        }
        else {
          FUN_8008fc9c((double)(float)piVar5[0x506],(double)(float)piVar5[0x507],piVar5 + 2,iVar9);
        }
        piVar5 = *ppiVar10;
        if (((piVar5 != (int *)0x0) && (piVar5[0x4fd] == 4)) &&
           (*(char *)((int)piVar5 + 0x144d) == '\0')) {
          cVar7 = cVar7 + '\x01';
        }
        iVar9 = iVar9 + 1;
        iVar6 = iVar6 + 4;
      }
      else {
        FUN_80090078(piVar5[0x4fc]);
        iVar9 = iVar9 + 1;
        iVar6 = iVar6 + 4;
      }
    }
    FLOAT_803dd194 = FLOAT_803df250;
    if (cVar7 != '\0') {
      FLOAT_803dd194 = FLOAT_803df1bc;
    }
    if ((DAT_803dd19c != 0) &&
       (*(short *)(DAT_803dd19c + 0x20) = *(short *)(DAT_803dd19c + 0x20) + 1,
       *(ushort *)(DAT_803dd19c + 0x22) <= *(ushort *)(DAT_803dd19c + 0x20))) {
      FUN_80023800();
      DAT_803dd19c = 0;
    }
    FLOAT_803dd1bc = FLOAT_803df254 * FLOAT_803db414 + FLOAT_803dd1bc;
    if (FLOAT_803df258 < FLOAT_803dd1bc) {
      FLOAT_803dd1bc = FLOAT_803dd1bc - FLOAT_803df258;
    }
    FLOAT_803dd1b8 = FLOAT_803df25c * FLOAT_803db414 + FLOAT_803dd1b8;
    if (FLOAT_803df258 < FLOAT_803dd1b8) {
      FLOAT_803dd1b8 = FLOAT_803dd1b8 - FLOAT_803df258;
    }
    FLOAT_803dd1b4 = -(FLOAT_803df260 * FLOAT_803db414 - FLOAT_803dd1b4);
    if (FLOAT_803dd1b4 < FLOAT_803df264) {
      FLOAT_803dd1b4 = FLOAT_803dd1b4 + FLOAT_803df258;
    }
    FLOAT_803db760 = FLOAT_803db760 + FLOAT_803dd194;
    if (FLOAT_803db760 <= FLOAT_803df1a4) {
      if (FLOAT_803db760 < FLOAT_803df1a0) {
        FLOAT_803db760 = FLOAT_803df1a0;
      }
    }
    else {
      FLOAT_803db760 = FLOAT_803df1a4;
    }
    DAT_803dd198 = 0;
    if ((piVar8 != (int *)0x0) && (piVar8[0x4fd] == 4)) {
      uVar2 = (uint)(FLOAT_803df1d4 * FLOAT_803db760);
      local_48 = (double)(longlong)(int)uVar2;
      DAT_803dd198 = (undefined)uVar2;
      if ((uVar2 & 0xff) != 0) {
        dVar13 = (double)((float)((double)FLOAT_803df1c4 *
                                 (double)(float)((double)FLOAT_803df1c8 *
                                                -(double)(float)((double)FLOAT_803df20c *
                                                                 (double)((float)piVar8[0x510] /
                                                                         FLOAT_803df210) +
                                                                (double)FLOAT_803df208))) /
                         FLOAT_803df268);
        DAT_8039a8f0 = FLOAT_803df1a0;
        DAT_8039a8f4 = FLOAT_803df244;
        DAT_8039a8f8 = FLOAT_803df1a0;
        uVar3 = FUN_8000f534((double)FLOAT_803df1a0,(double)FLOAT_803df20c,(double)FLOAT_803df1c8,
                             (double)FLOAT_803df1c4);
        if (piVar8[0x4fd] == 0) {
          FLOAT_803dd190 = FLOAT_803df200 * FLOAT_803df26c * FLOAT_803db414 + FLOAT_803dd190;
          FLOAT_803db764 = FLOAT_803df270;
          DAT_803dd199 = 0xf9;
          DAT_803dd19a = 0xfd;
          FLOAT_803db768 = FLOAT_803df274;
          FUN_80246e54(auStack132);
        }
        else {
          FLOAT_803dd190 = FLOAT_803df26c * FLOAT_803db414 + FLOAT_803dd190;
          FLOAT_803db764 = FLOAT_803df1a4;
          DAT_803dd199 = 0xf8;
          DAT_803dd19a = 0xfc;
          FLOAT_803db768 = FLOAT_803df1a4;
          FUN_802470c8(dVar13,auStack132,0x7a);
        }
        FUN_80246eb4(uVar3,auStack132,auStack132);
        FUN_80247494(auStack132,&DAT_8039a8f0,&DAT_8039a8f0);
        if (FLOAT_803dd190 < FLOAT_803df278) {
          FLOAT_803dd190 = FLOAT_803dd190 + FLOAT_803df1e8;
        }
      }
    }
    if ((DAT_803dd19b == '\0') || (DAT_803dd1cc != '\0')) {
      if ((DAT_803dd19b == '\0') && (DAT_803dd1cc != '\0')) {
        FUN_8000a518(0xeb,0);
      }
    }
    else {
      FUN_8000a518(0xeb,1);
    }
  }
  __psq_l0(auStack8,uVar11);
  __psq_l1(auStack8,uVar11);
  FUN_80286118();
  return;
}

