// Function: FUN_801f73d4
// Entry: 801f73d4
// Size: 1408 bytes

/* WARNING: Removing unreachable block (ram,0x801f7934) */

void FUN_801f73d4(void)

{
  char cVar1;
  byte bVar2;
  short *psVar3;
  int iVar4;
  int unaff_r27;
  short sVar5;
  short sVar6;
  int iVar7;
  undefined4 uVar8;
  undefined8 in_f31;
  double dVar9;
  undefined auStack8 [8];
  
  uVar8 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  psVar3 = (short *)FUN_802860dc();
  iVar7 = *(int *)(psVar3 + 0x5c);
  sVar6 = 0;
  sVar5 = 1;
  dVar9 = (double)FLOAT_803e5f20;
  if (psVar3[0x23] == 0x262) {
    iVar4 = FUN_8001ffb4(0x38f);
    if (iVar4 == 0) {
      iVar4 = FUN_800394ac(psVar3,1,0);
      if ((iVar4 != 0) &&
         (*(short *)(iVar4 + 10) = *(short *)(iVar4 + 10) + -0x10, *(short *)(iVar4 + 10) < -0x3e0))
      {
        *(undefined2 *)(iVar4 + 10) = 0;
      }
      iVar4 = FUN_8001ffb4(0x21b);
      if (iVar4 != 0) {
        sVar6 = 100;
      }
      iVar4 = FUN_8001ffb4(0x21c);
      if (iVar4 != 0) {
        sVar6 = 200;
      }
      iVar4 = FUN_8001ffb4(0x21d);
      if (iVar4 != 0) {
        sVar6 = 400;
      }
      iVar4 = FUN_8001ffb4(0x21f);
      if (iVar4 != 0) {
        sVar6 = 800;
      }
      iVar4 = FUN_8001ffb4(0x221);
      if (iVar4 != 0) {
        sVar6 = 0x640;
      }
      iVar4 = FUN_8001ffb4(0x222);
      if (iVar4 != 0) {
        sVar6 = 0x1900;
        sVar5 = 3;
        dVar9 = (double)FLOAT_803e5f78;
      }
      if (*(short *)(iVar7 + 2) < sVar6) {
        *(ushort *)(iVar7 + 2) = *(short *)(iVar7 + 2) + (ushort)DAT_803db410 * sVar5;
        *(float *)(psVar3 + 4) =
             -(float)(dVar9 * (double)FLOAT_803db414 - (double)*(float *)(psVar3 + 4));
        *(float *)(psVar3 + 8) =
             FLOAT_803e5f7c * (float)(dVar9 * (double)FLOAT_803db414) + *(float *)(psVar3 + 8);
      }
      else {
        iVar4 = FUN_8001ffb4(0x222);
        if ((iVar4 != 0) && (iVar4 = FUN_8001ffb4(0x38d), iVar4 == 0)) {
          FUN_800200e8(0x38d,1);
          FUN_800200e8(0x370,0);
          *(undefined *)(iVar7 + 0xd) = 0;
        }
      }
      iVar4 = FUN_8001ffb4(0x38d);
      if (((iVar4 == 0) && (0x960 < *(short *)(iVar7 + 2))) &&
         (iVar4 = FUN_800221a0(0,100), iVar4 == 0)) {
        FUN_8000e67c((double)(FLOAT_803e5f80 *
                             ((float)((double)CONCAT44(0x43300000,
                                                       (int)*(short *)(iVar7 + 2) - 0x960U ^
                                                       0x80000000) - DOUBLE_803e5f70) /
                             FLOAT_803e5f84)));
        FUN_800200e8(0x370,1);
      }
      *psVar3 = *psVar3 + *(short *)(iVar7 + 2);
      if (*(char *)(iVar7 + 0xd) == '\0') {
        FUN_8002cbc4(psVar3);
      }
    }
    else {
      FUN_8002cbc4(psVar3);
    }
    goto LAB_801f7934;
  }
  if (psVar3[0x23] == 0x2c2) {
    iVar7 = FUN_8001ffb4(0x38f);
    if (iVar7 != 0) {
      if (*(byte *)(psVar3 + 0x1b) < 0xfa) {
        unaff_r27 = (int)(short)((ushort)*(byte *)(psVar3 + 0x1b) + (ushort)DAT_803db410);
      }
      if (0xfa < unaff_r27) {
        unaff_r27 = 0xfa;
      }
      *(char *)(psVar3 + 0x1b) = (char)unaff_r27;
      iVar7 = FUN_800394ac(psVar3,0,0);
      if ((iVar7 != 0) &&
         (*(ushort *)(iVar7 + 8) = *(short *)(iVar7 + 8) + (ushort)DAT_803db410 * -8,
         *(short *)(iVar7 + 8) < -0x3e0)) {
        *(undefined2 *)(iVar7 + 8) = 0;
      }
    }
    goto LAB_801f7934;
  }
  iVar4 = FUN_8001ffb4(0x38f);
  if (iVar4 == 0) {
    psVar3[2] = psVar3[2] + *(short *)(iVar7 + 4);
    *psVar3 = *psVar3 + *(short *)(iVar7 + 2);
    iVar7 = FUN_8001ffb4(0x38d);
    if ((iVar7 != 0) && (*(char *)((int)psVar3 + 0xad) == '\0')) {
      if (DAT_803ddcaa == 0) {
        if ((600 < DAT_803ddca8) && (iVar7 = FUN_800221a0(0,10), iVar7 == 0)) {
          FUN_8000e67c((double)FLOAT_803e5f88);
        }
        if ((0 < DAT_803ddca8) &&
           (DAT_803ddca8 = DAT_803ddca8 - (ushort)DAT_803db410, DAT_803ddca8 < 1)) {
          DAT_803ddca8 = 0;
          FUN_800200e8(0x38d,0);
          FUN_800200e8(0x38f,1);
        }
      }
      if (DAT_803ddcb0 == 0) {
        if ((0 < DAT_803ddcae) &&
           (DAT_803ddcae = DAT_803ddcae - (ushort)DAT_803db410, DAT_803ddcae < 0)) {
          DAT_803ddcae = 0;
        }
      }
      else {
        if ((0 < DAT_803ddcb0) &&
           (DAT_803ddcb0 = DAT_803ddcb0 - (ushort)DAT_803db410, DAT_803ddcb0 < 1)) {
          DAT_803ddcb0 = 0;
          FUN_80008cbc(psVar3,psVar3,0x30,0);
          FUN_80008cbc(psVar3,psVar3,0x34,0);
        }
        iVar7 = FUN_800221a0(0,8);
        if (iVar7 == 0) {
          FUN_8000e67c((double)FLOAT_803e5f88);
        }
      }
    }
    goto LAB_801f7934;
  }
  cVar1 = *(char *)((int)psVar3 + 0xad);
  if (cVar1 == '\0') {
    bVar2 = *(byte *)(psVar3 + 0x1b);
    if (bVar2 == 0xff) goto LAB_801f76f0;
    if (bVar2 != 0xff) {
      unaff_r27 = (int)(short)((ushort)bVar2 + (ushort)DAT_803db410);
    }
    if (0xff < unaff_r27) {
      unaff_r27 = 0xff;
    }
    *(char *)(psVar3 + 0x1b) = (char)unaff_r27;
  }
  else {
LAB_801f76f0:
    if (cVar1 == '\x01') {
      bVar2 = *(byte *)(psVar3 + 0x1b);
      if (bVar2 != 0x55) {
        if (bVar2 < 0x55) {
          unaff_r27 = (int)(short)((ushort)bVar2 + (ushort)DAT_803db410);
        }
        if (0x55 < unaff_r27) {
          unaff_r27 = 0x55;
        }
        *(char *)(psVar3 + 0x1b) = (char)unaff_r27;
        goto LAB_801f776c;
      }
    }
    if (cVar1 == '\x02') {
      bVar2 = *(byte *)(psVar3 + 0x1b);
      if (bVar2 != 0x19) {
        if (bVar2 < 0x19) {
          unaff_r27 = (int)(short)((ushort)bVar2 + (ushort)DAT_803db410);
        }
        if (0x19 < unaff_r27) {
          unaff_r27 = 0x19;
        }
        *(char *)(psVar3 + 0x1b) = (char)unaff_r27;
      }
    }
  }
LAB_801f776c:
  if (*(char *)((int)psVar3 + 0xad) == '\0') {
    iVar7 = FUN_800221a0(0,0x96);
    if (iVar7 == 0) {
      FUN_800221a0(0,0xffff);
      FUN_800221a0(0,0xffff);
      FUN_800221a0(0,0xffff);
      FUN_8000bb18(psVar3,0x81);
    }
    FUN_801f6ea4(psVar3);
  }
LAB_801f7934:
  __psq_l0(auStack8,uVar8);
  __psq_l1(auStack8,uVar8);
  FUN_80286128();
  return;
}

