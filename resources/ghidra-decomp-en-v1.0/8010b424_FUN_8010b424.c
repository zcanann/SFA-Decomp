// Function: FUN_8010b424
// Entry: 8010b424
// Size: 1652 bytes

/* WARNING: Removing unreachable block (ram,0x8010ba70) */
/* WARNING: Removing unreachable block (ram,0x8010ba60) */
/* WARNING: Removing unreachable block (ram,0x8010ba68) */
/* WARNING: Removing unreachable block (ram,0x8010ba78) */

void FUN_8010b424(void)

{
  float fVar1;
  byte bVar2;
  short *psVar3;
  undefined4 uVar4;
  undefined4 uVar5;
  int iVar6;
  short sVar8;
  uint uVar7;
  int iVar9;
  undefined4 uVar10;
  double dVar11;
  double dVar12;
  undefined8 uVar13;
  undefined8 in_f28;
  undefined8 in_f29;
  double dVar14;
  undefined8 in_f30;
  double dVar15;
  undefined8 in_f31;
  undefined auStack264 [16];
  undefined auStack248 [16];
  undefined auStack232 [16];
  undefined auStack216 [16];
  undefined auStack200 [16];
  undefined auStack184 [16];
  undefined auStack168 [16];
  int local_98 [2];
  int local_90;
  int local_8c;
  int local_88 [2];
  int local_80;
  int local_7c;
  double local_78;
  undefined4 local_70;
  uint uStack108;
  longlong local_68;
  undefined auStack56 [16];
  undefined auStack40 [16];
  undefined auStack24 [16];
  undefined auStack8 [8];
  
  uVar10 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  __psq_st0(auStack24,(int)((ulonglong)in_f30 >> 0x20),0);
  __psq_st1(auStack24,(int)in_f30,0);
  __psq_st0(auStack40,(int)((ulonglong)in_f29 >> 0x20),0);
  __psq_st1(auStack40,(int)in_f29,0);
  __psq_st0(auStack56,(int)((ulonglong)in_f28 >> 0x20),0);
  __psq_st1(auStack56,(int)in_f28,0);
  psVar3 = (short *)FUN_802860d8();
  if (*(char *)((int)DAT_803dd560 + 0x65) == '\0') {
    iVar9 = *(int *)(psVar3 + 0x52);
    FUN_80014e70(0);
    uVar4 = (**(code **)(*DAT_803dca9c + 0x1c))(DAT_803dd560[3]);
    uVar5 = (**(code **)(*DAT_803dca9c + 0x1c))(DAT_803dd560[2]);
    FUN_8010aa54(uVar5,local_98,DAT_803dd560[1]);
    FUN_8010aa54(uVar4,local_88,DAT_803dd560[1]);
    FUN_8010a590(local_98,auStack168,auStack184,auStack200,auStack216,auStack232,auStack248,
                 auStack264);
    dVar12 = (double)FUN_8010ac48((double)*(float *)(iVar9 + 0x18),(double)*(float *)(iVar9 + 0x1c),
                                  (double)*(float *)(iVar9 + 0x20),local_88);
    dVar11 = (double)FLOAT_803e1888;
    if (dVar11 <= dVar12) {
      dVar11 = dVar12;
      if ((double)FLOAT_803e188c < dVar12) {
        if ((local_80 < 0) || (local_7c < 0)) {
          dVar11 = (double)FLOAT_803e188c;
        }
        else {
          DAT_803dd560[3] = local_80;
          uVar4 = (**(code **)(*DAT_803dca9c + 0x1c))(DAT_803dd560[3]);
          FUN_8010aa54(uVar4,local_88,DAT_803dd560[1]);
          if ((local_90 < 0) || (local_8c < 0)) {
            dVar11 = (double)FLOAT_803e188c;
          }
          else {
            DAT_803dd560[2] = local_90;
            uVar4 = (**(code **)(*DAT_803dca9c + 0x1c))(DAT_803dd560[2]);
            FUN_8010aa54(uVar4,local_98,DAT_803dd560[1]);
            FUN_8010a590(local_98,auStack168,auStack184,auStack200,auStack216,auStack232,auStack248,
                         auStack264);
            dVar11 = (double)FUN_8010ac48((double)*(float *)(iVar9 + 0x18),
                                          (double)*(float *)(iVar9 + 0x1c),
                                          (double)*(float *)(iVar9 + 0x20),local_88);
            DAT_803dd560[0x16] = (int)((float)DAT_803dd560[0x16] - FLOAT_803e188c);
          }
        }
      }
    }
    else if (-1 < local_88[0]) {
      DAT_803dd560[3] = local_88[0];
      uVar4 = (**(code **)(*DAT_803dca9c + 0x1c))(DAT_803dd560[3]);
      FUN_8010aa54(uVar4,local_88,DAT_803dd560[1]);
      if (local_98[0] < 0) {
        dVar11 = (double)FLOAT_803e1888;
      }
      else {
        DAT_803dd560[2] = local_98[0];
        uVar4 = (**(code **)(*DAT_803dca9c + 0x1c))(DAT_803dd560[2]);
        FUN_8010aa54(uVar4,local_98,DAT_803dd560[1]);
        FUN_8010a590(local_98,auStack168,auStack184,auStack200,auStack216,auStack232,auStack248,
                     auStack264);
        dVar11 = (double)FUN_8010ac48((double)*(float *)(iVar9 + 0x18),
                                      (double)*(float *)(iVar9 + 0x1c),
                                      (double)*(float *)(iVar9 + 0x20),local_88);
        DAT_803dd560[0x16] = (int)((float)DAT_803dd560[0x16] + FLOAT_803e188c);
      }
    }
    fVar1 = (float)((double)FLOAT_803e18bc *
                    (double)(float)(dVar11 - (double)(float)DAT_803dd560[0x16]) +
                   (double)(float)DAT_803dd560[0x16]);
    dVar12 = (double)fVar1;
    DAT_803dd560[0x16] = (int)fVar1;
    dVar11 = (double)FUN_80010ee0(dVar12,auStack168,0);
    *(float *)(psVar3 + 0xc) = (float)dVar11;
    dVar11 = (double)FUN_80010ee0(dVar12,auStack184,0);
    *(float *)(psVar3 + 0xe) = (float)dVar11;
    dVar11 = (double)FUN_80010ee0(dVar12,auStack200,0);
    *(float *)(psVar3 + 0x10) = (float)dVar11;
    iVar6 = (**(code **)(*DAT_803dca9c + 0x1c))(DAT_803dd560[2]);
    bVar2 = *(byte *)(iVar6 + 0x3b);
    if ((bVar2 & 1) == 0) {
      dVar11 = (double)FUN_80010c64(dVar12,auStack216,0);
      local_78 = (double)(longlong)(int)dVar11;
      *psVar3 = (short)(int)dVar11 + -0x8000;
    }
    if ((bVar2 & 2) == 0) {
      dVar11 = (double)FUN_80010c64(dVar12,auStack232,0);
      local_78 = (double)(longlong)(int)dVar11;
      psVar3[1] = (short)(int)dVar11;
    }
    if ((bVar2 & 4) == 0) {
      dVar11 = (double)FUN_80010c64(dVar12,auStack248,0);
      local_78 = (double)(longlong)(int)dVar11;
      psVar3[2] = (short)(int)dVar11;
    }
    dVar11 = (double)FUN_80010ee0(dVar12,auStack264,0);
    *(float *)(psVar3 + 0x5a) = (float)dVar11;
    if ((*(char *)(DAT_803dd560 + 0x19) == '\0') && (iVar6 = FUN_8010aea8(psVar3,bVar2), iVar6 != 0)
       ) {
      *(undefined *)(DAT_803dd560 + 0x19) = 1;
    }
    dVar15 = (double)(*(float *)(psVar3 + 0xc) - *(float *)(iVar9 + 0x18));
    dVar14 = (double)(*(float *)(psVar3 + 0xe) - *(float *)(iVar9 + 0x1c));
    dVar11 = (double)(*(float *)(psVar3 + 0x10) - *(float *)(iVar9 + 0x20));
    if ((bVar2 & 1) != 0) {
      sVar8 = FUN_800217c0(dVar15,dVar11);
      *psVar3 = -0x8000 - sVar8;
    }
    if ((bVar2 & 2) != 0) {
      uVar13 = FUN_802931a0((double)(float)(dVar15 * dVar15 + (double)(float)(dVar11 * dVar11)));
      uVar7 = FUN_800217c0(dVar14,uVar13);
      dVar11 = (double)FUN_80010c64(dVar12,auStack232,0);
      local_78 = (double)CONCAT44(0x43300000,uVar7 & 0xffff ^ 0x80000000);
      uStack108 = (int)psVar3[1] & 0xffffU ^ 0x80000000;
      local_70 = 0x43300000;
      iVar6 = (int)((float)((double)(float)(local_78 - DOUBLE_803e18a0) - dVar11) -
                   (float)((double)CONCAT44(0x43300000,uStack108) - DOUBLE_803e18a0));
      local_68 = (longlong)iVar6;
      if (0x8000 < iVar6) {
        iVar6 = iVar6 + -0xffff;
      }
      if (iVar6 < -0x8000) {
        iVar6 = iVar6 + 0xffff;
      }
      psVar3[1] = psVar3[1] + (short)((int)(iVar6 * (uint)DAT_803db410) >> 3);
    }
    if ((bVar2 & 4) != 0) {
      iVar9 = (int)psVar3[2] - ((int)*(short *)(iVar9 + 4) & 0xffffU);
      if (0x8000 < iVar9) {
        iVar9 = iVar9 + -0xffff;
      }
      if (iVar9 < -0x8000) {
        iVar9 = iVar9 + 0xffff;
      }
      psVar3[2] = psVar3[2] + (short)((int)(iVar9 * (uint)DAT_803db410) >> 3);
    }
    if (*DAT_803dd560 != 0) {
      uVar4 = *(undefined4 *)(psVar3 + 0xc);
      *(undefined4 *)(*DAT_803dd560 + 0x18) = uVar4;
      *(undefined4 *)(*DAT_803dd560 + 0xc) = uVar4;
      uVar4 = *(undefined4 *)(psVar3 + 0xe);
      *(undefined4 *)(*DAT_803dd560 + 0x1c) = uVar4;
      *(undefined4 *)(*DAT_803dd560 + 0x10) = uVar4;
      uVar4 = *(undefined4 *)(psVar3 + 0x10);
      *(undefined4 *)(*DAT_803dd560 + 0x20) = uVar4;
      *(undefined4 *)(*DAT_803dd560 + 0x14) = uVar4;
    }
    FUN_8000e034((double)*(float *)(psVar3 + 0xc),(double)*(float *)(psVar3 + 0xe),
                 (double)*(float *)(psVar3 + 0x10),psVar3 + 6,psVar3 + 8,psVar3 + 10,
                 *(undefined4 *)(psVar3 + 0x18));
  }
  else {
    (**(code **)(*DAT_803dca50 + 0x1c))(0x42,0,1,0,0,0,0xff);
  }
  __psq_l0(auStack8,uVar10);
  __psq_l1(auStack8,uVar10);
  __psq_l0(auStack24,uVar10);
  __psq_l1(auStack24,uVar10);
  __psq_l0(auStack40,uVar10);
  __psq_l1(auStack40,uVar10);
  __psq_l0(auStack56,uVar10);
  __psq_l1(auStack56,uVar10);
  FUN_80286124();
  return;
}

