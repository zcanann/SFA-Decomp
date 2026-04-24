// Function: FUN_80157004
// Entry: 80157004
// Size: 1364 bytes

/* WARNING: Removing unreachable block (ram,0x80157538) */

void FUN_80157004(void)

{
  float fVar1;
  bool bVar2;
  short *psVar3;
  uint uVar4;
  uint uVar5;
  int iVar6;
  short sVar7;
  char cVar8;
  int iVar9;
  undefined4 uVar10;
  undefined8 in_f31;
  double dVar11;
  undefined8 uVar12;
  float local_130;
  float local_12c;
  float local_128;
  float local_124;
  float local_120;
  undefined4 local_11c;
  undefined4 local_118;
  undefined4 local_114;
  float local_110;
  float local_10c;
  float local_108;
  undefined4 local_104;
  undefined4 local_100;
  undefined4 local_fc;
  float local_f8;
  float local_f4;
  float local_f0;
  undefined auStack236 [84];
  undefined auStack152 [88];
  double local_40;
  undefined4 local_38;
  uint uStack52;
  undefined auStack8 [8];
  
  uVar10 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  uVar12 = FUN_802860dc();
  psVar3 = (short *)((ulonglong)uVar12 >> 0x20);
  iVar9 = (int)uVar12;
  uStack52 = (uint)*(byte *)(*(int *)(psVar3 + 0x26) + 0x2f);
  local_40 = (double)CONCAT44(0x43300000,uStack52);
  local_38 = 0x43300000;
  fVar1 = (float)(local_40 - DOUBLE_803e2b58);
  if (FLOAT_803e2b18 == (float)((double)CONCAT44(0x43300000,uStack52) - DOUBLE_803e2b58)) {
    fVar1 = FLOAT_803e2b38;
  }
  dVar11 = (double)(fVar1 / FLOAT_803e2b38);
  *(float *)(iVar9 + 0x324) = *(float *)(iVar9 + 0x324) - FLOAT_803db414;
  if (*(float *)(iVar9 + 0x324) <= FLOAT_803e2b18) {
    uStack52 = FUN_800221a0(0x3c,0x78);
    uStack52 = uStack52 ^ 0x80000000;
    *(float *)(iVar9 + 0x324) = (float)((double)CONCAT44(0x43300000,uStack52) - DOUBLE_803e2b20);
  }
  local_38 = 0x43300000;
  if (FLOAT_803e2b18 == *(float *)(iVar9 + 0x328)) {
    bVar2 = false;
  }
  else {
    FUN_80035f00(psVar3);
    if (psVar3[0x50] == 5) {
      if ((*(uint *)(iVar9 + 0x2dc) & 0x40000000) != 0) {
        FUN_80035f20(psVar3);
        *(float *)(iVar9 + 0x328) = FLOAT_803e2b18;
      }
    }
    else {
      FUN_8014d08c((double)FLOAT_803dbcec,psVar3,iVar9,5,0,0);
    }
    *(undefined *)(psVar3 + 0x1b) = 0xff;
    bVar2 = true;
  }
  if (!bVar2) {
    *psVar3 = *psVar3 + *(short *)(iVar9 + 0x338);
    local_104 = *(undefined4 *)(psVar3 + 6);
    local_100 = *(undefined4 *)(psVar3 + 8);
    local_fc = *(undefined4 *)(psVar3 + 10);
    FUN_80292e20(*psVar3,&local_128,&local_124);
    local_f8 = -(FLOAT_803e2b38 * local_128 - *(float *)(psVar3 + 6));
    local_f4 = FLOAT_803e2b3c + *(float *)(psVar3 + 8);
    local_f0 = -(FLOAT_803e2b38 * local_124 - *(float *)(psVar3 + 10));
    uVar4 = FUN_800640cc((double)FLOAT_803e2b18,&local_104,&local_f8,3,auStack152,psVar3,
                         *(undefined *)(iVar9 + 0x261),0xffffffff,0xff,0);
    uVar4 = countLeadingZeros(uVar4 & 0xff);
    uVar4 = uVar4 >> 5 & 0xff;
    uVar5 = FUN_800217c0((double)(*(float *)(psVar3 + 6) - *(float *)(*(int *)(iVar9 + 0x29c) + 0xc)
                                 ),
                         (double)(*(float *)(psVar3 + 10) -
                                 *(float *)(*(int *)(iVar9 + 0x29c) + 0x14)));
    uStack52 = (uVar5 & 0xffff) - ((int)*psVar3 & 0xffffU) ^ 0x80000000;
    local_38 = 0x43300000;
    fVar1 = (float)((double)CONCAT44(0x43300000,uStack52) - DOUBLE_803e2b20);
    if (FLOAT_803e2b2c < fVar1) {
      fVar1 = FLOAT_803e2b28 + fVar1;
    }
    if (fVar1 < FLOAT_803e2b34) {
      fVar1 = FLOAT_803e2b30 + fVar1;
    }
    local_40 = (double)(longlong)(int)fVar1;
    sVar7 = (short)(int)fVar1;
    uVar5 = (uint)sVar7;
    if ((int)uVar5 < 0) {
      uVar5 = -uVar5;
    }
    uVar5 = uVar5 & 0xffff;
    FUN_8002b9ec();
    iVar6 = FUN_80295c88();
    if (iVar6 != 0) {
      local_120 = FLOAT_803e2b48;
      iVar6 = FUN_80036e58(0x30,psVar3,&local_120);
      if (iVar6 != 0) {
        sVar7 = FUN_800385e8(psVar3,iVar6,&local_120);
        if (sVar7 < -300) {
          sVar7 = -300;
        }
        else if (300 < sVar7) {
          sVar7 = 300;
        }
        iVar6 = (int)sVar7;
        *(short *)(iVar9 + 0x338) = sVar7;
        if (iVar6 < 0) {
          iVar6 = -iVar6;
        }
        if (iVar6 < 0x4000) {
          *psVar3 = -*psVar3;
          local_11c = *(undefined4 *)(psVar3 + 6);
          local_118 = *(undefined4 *)(psVar3 + 8);
          local_114 = *(undefined4 *)(psVar3 + 10);
          FUN_80292e20(*psVar3,&local_130,&local_12c);
          local_110 = -(FLOAT_803e2b38 * local_130 - *(float *)(psVar3 + 6));
          local_10c = FLOAT_803e2b3c + *(float *)(psVar3 + 8);
          local_108 = -(FLOAT_803e2b38 * local_12c - *(float *)(psVar3 + 10));
          cVar8 = FUN_800640cc((double)FLOAT_803e2b18,&local_11c,&local_110,3,auStack236,psVar3,
                               *(undefined *)(iVar9 + 0x261),0xffffffff,0xff,0);
          if (cVar8 == '\0') {
            if ((*(uint *)(iVar9 + 0x2dc) & 0x40000000) != 0) {
              FUN_8014d08c((double)(FLOAT_803e2b40 / (float)((double)FLOAT_803e2b4c * dVar11)),
                           psVar3,iVar9,7,0,1);
            }
            psVar3[1] = *(short *)(iVar9 + 0x19c);
            psVar3[2] = *(short *)(iVar9 + 0x19e);
          }
          *psVar3 = -*psVar3;
        }
        goto LAB_80157538;
      }
    }
    if ((*(int *)(iVar9 + 0x29c) != 0) &&
       (FLOAT_803e2b50 < *(float *)(*(int *)(iVar9 + 0x29c) + 0xa8))) {
      *(float *)(iVar9 + 0x2ac) = FLOAT_803dbce8;
    }
    if ((((*(uint *)(iVar9 + 0x2dc) & 0x40000000) != 0) || (uVar4 == 0)) ||
       ((uVar5 < 3000 && ((uVar4 != 0 && (psVar3[0x50] != 0)))))) {
      if ((uVar4 == 0) || (2999 < uVar5)) {
        FUN_8014d08c((double)(float)((double)FLOAT_803e2b44 / dVar11),psVar3,iVar9,1,0,0);
        fVar1 = FLOAT_803e2b18;
        *(float *)(psVar3 + 0x12) = FLOAT_803e2b18;
        *(float *)(psVar3 + 0x14) = fVar1;
        *(float *)(psVar3 + 0x16) = fVar1;
        if (uVar5 < 3000) {
          sVar7 = FUN_800221a0(0,1);
          *(short *)(iVar9 + 0x338) = (sVar7 + -1) * 300;
        }
        else if (sVar7 < 0) {
          *(undefined2 *)(iVar9 + 0x338) = 0xfed4;
        }
        else {
          *(undefined2 *)(iVar9 + 0x338) = 300;
        }
      }
      else {
        *(undefined2 *)(iVar9 + 0x338) = 0;
        FUN_8014d08c((double)(float)((double)FLOAT_803e2b40 / dVar11),psVar3,iVar9,0,0,1);
      }
    }
    psVar3[1] = *(short *)(iVar9 + 0x19c);
    psVar3[2] = *(short *)(iVar9 + 0x19e);
  }
LAB_80157538:
  __psq_l0(auStack8,uVar10);
  __psq_l1(auStack8,uVar10);
  FUN_80286128();
  return;
}

