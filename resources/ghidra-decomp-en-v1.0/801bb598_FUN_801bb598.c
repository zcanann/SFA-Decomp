// Function: FUN_801bb598
// Entry: 801bb598
// Size: 1452 bytes

/* WARNING: Removing unreachable block (ram,0x801bbb1c) */
/* WARNING: Removing unreachable block (ram,0x801bbb0c) */
/* WARNING: Removing unreachable block (ram,0x801bbb14) */
/* WARNING: Removing unreachable block (ram,0x801bbb24) */

void FUN_801bb598(void)

{
  float fVar1;
  short sVar2;
  short sVar5;
  undefined4 uVar3;
  undefined4 uVar4;
  int iVar6;
  int *piVar7;
  undefined4 uVar8;
  undefined8 in_f28;
  double dVar9;
  undefined8 in_f29;
  double dVar10;
  undefined8 in_f30;
  double dVar11;
  undefined8 in_f31;
  double dVar12;
  undefined8 uVar13;
  undefined uStack184;
  undefined local_b7;
  undefined local_b6;
  undefined local_b5;
  undefined auStack180 [12];
  float local_a8;
  float local_98;
  float local_88;
  undefined4 local_80;
  uint uStack124;
  undefined4 local_78;
  uint uStack116;
  undefined auStack56 [16];
  undefined auStack40 [16];
  undefined auStack24 [16];
  undefined auStack8 [8];
  
  uVar8 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  __psq_st0(auStack24,(int)((ulonglong)in_f30 >> 0x20),0);
  __psq_st1(auStack24,(int)in_f30,0);
  __psq_st0(auStack40,(int)((ulonglong)in_f29 >> 0x20),0);
  __psq_st1(auStack40,(int)in_f29,0);
  __psq_st0(auStack56,(int)((ulonglong)in_f28 >> 0x20),0);
  __psq_st1(auStack56,(int)in_f28,0);
  uVar13 = FUN_802860c0();
  uVar4 = (undefined4)((ulonglong)uVar13 >> 0x20);
  piVar7 = *(int **)((int)uVar13 + 0x40c);
  if (*piVar7 != 0) {
    if (*(short *)((int)uVar13 + 0x402) == 1) {
      FUN_8001dd88((double)(float)piVar7[0x16],(double)(float)piVar7[0x17],
                   (double)(float)piVar7[0x18]);
    }
    else {
      FUN_8001dd88((double)(float)piVar7[0x10],(double)(float)piVar7[0x11],
                   (double)(float)piVar7[0x12]);
    }
    FUN_8001d9f4(*piVar7,&local_b5,&local_b6,&local_b7,&uStack184);
    FUN_8001d71c(*piVar7,local_b5,local_b6,local_b7,0xc0);
    iVar6 = *piVar7;
    if ((*(char *)(iVar6 + 0x2f8) != '\0') && (*(char *)(iVar6 + 0x4c) != '\0')) {
      sVar2 = (ushort)*(byte *)(iVar6 + 0x2f9) + (short)*(char *)(iVar6 + 0x2fa);
      if (sVar2 < 0) {
        sVar2 = 0;
        *(undefined *)(iVar6 + 0x2fa) = 0;
      }
      else if (0xc < sVar2) {
        sVar5 = FUN_800221a0(0xfffffff4,0xc);
        sVar2 = sVar2 + sVar5;
        if (0xff < sVar2) {
          sVar2 = 0xff;
          *(undefined *)(*piVar7 + 0x2fa) = 0;
        }
      }
      *(char *)(*piVar7 + 0x2f9) = (char)sVar2;
    }
  }
  if ((DAT_803ddb80 & 0x200) != 0) {
    FUN_8003842c(uVar4,7,&DAT_803ac988,&DAT_803ac98c,&DAT_803ac990,0);
    iVar6 = 0;
    do {
      (**(code **)(*DAT_803dca88 + 8))(uVar4,0x4b7,&DAT_803ac97c,0x200001,0xffffffff,0);
      iVar6 = iVar6 + 1;
    } while (iVar6 < 0xf);
  }
  if ((DAT_803ddb80 & 0x400) != 0) {
    FUN_8003842c(uVar4,8,&DAT_803ac988,&DAT_803ac98c,&DAT_803ac990,0);
    iVar6 = 0;
    do {
      (**(code **)(*DAT_803dca88 + 8))(uVar4,0x4b7,&DAT_803ac97c,0x200001,0xffffffff,0);
      iVar6 = iVar6 + 1;
    } while (iVar6 < 0xf);
  }
  if ((DAT_803ddb80 & 0x800) != 0) {
    FUN_8003842c(uVar4,9,&DAT_803ac988,&DAT_803ac98c,&DAT_803ac990,0);
    iVar6 = 0;
    do {
      (**(code **)(*DAT_803dca88 + 8))(uVar4,0x4b7,&DAT_803ac97c,0x200001,0xffffffff,0);
      iVar6 = iVar6 + 1;
    } while (iVar6 < 0xf);
  }
  if ((DAT_803ddb80 & 0x1000) != 0) {
    FUN_8003842c(uVar4,10,&DAT_803ac988,&DAT_803ac98c,&DAT_803ac990,0);
    iVar6 = 0;
    do {
      (**(code **)(*DAT_803dca88 + 8))(uVar4,0x4b7,&DAT_803ac97c,0x200001,0xffffffff,0);
      iVar6 = iVar6 + 1;
    } while (iVar6 < 0xf);
  }
  if ((DAT_803ddb80 & 0x10) != 0) {
    uVar3 = FUN_800383a0(uVar4,0xb);
    FUN_80003494(auStack180,uVar3,0x30);
    local_a8 = FLOAT_803e4bd8;
    local_98 = FLOAT_803e4bd8;
    local_88 = FLOAT_803e4bd8;
    iVar6 = 0;
    dVar10 = (double)FLOAT_803e4c34;
    dVar11 = (double)(float)(dVar10 * (double)FLOAT_803e4c38);
    dVar12 = (double)FLOAT_803e4bcc;
    dVar9 = DOUBLE_803e4be0;
    do {
      uStack124 = FUN_800221a0(0xffffffe7,0x19);
      uStack124 = uStack124 ^ 0x80000000;
      local_80 = 0x43300000;
      DAT_803ac988 = (float)((double)CONCAT44(0x43300000,uStack124) - dVar9);
      uStack116 = FUN_800221a0(0xffffffe7,0x19);
      uStack116 = uStack116 ^ 0x80000000;
      local_78 = 0x43300000;
      DAT_803ac98c = (float)((double)CONCAT44(0x43300000,uStack116) - dVar9);
      DAT_803ac990 = (float)dVar10;
      DAT_803ac970 = (float)((double)DAT_803ac988 / dVar11);
      DAT_803ac974 = (float)((double)DAT_803ac98c / dVar11);
      DAT_803ac978 = (float)dVar12;
      FUN_80247494(auStack180,&DAT_803ac970,&DAT_803ac970);
      FUN_8003842c(uVar4,0xb,&DAT_803ac988,&DAT_803ac98c,&DAT_803ac990,1);
      (**(code **)(*DAT_803dca88 + 8))(uVar4,0x4b8,&DAT_803ac97c,0x200001,0xffffffff,&DAT_803ac970);
      iVar6 = iVar6 + 1;
    } while (iVar6 < 5);
  }
  piVar7[10] = (int)FLOAT_803e4bd8;
  piVar7[0xb] = (int)FLOAT_803e4c3c;
  piVar7[0xc] = (int)FLOAT_803e4c40;
  piVar7[9] = (int)FLOAT_803e4c44;
  *(undefined2 *)(piVar7 + 8) = 0;
  *(undefined2 *)((int)piVar7 + 0x1e) = 0;
  *(undefined2 *)(piVar7 + 7) = 0;
  FUN_8003842c(uVar4,0xd,piVar7 + 10,piVar7 + 0xb,piVar7 + 0xc,1);
  FUN_8003842c(uVar4,0xd,piVar7 + 4,piVar7 + 5,piVar7 + 6,0);
  FUN_8003842c(uVar4,0xb,piVar7 + 0x10,piVar7 + 0x11,piVar7 + 0x12,0);
  piVar7[0x16] = (int)FLOAT_803e4bd8;
  piVar7[0x17] = (int)FLOAT_803e4c48;
  piVar7[0x18] = (int)FLOAT_803e4bc8;
  piVar7[0x15] = (int)FLOAT_803e4c44;
  *(undefined2 *)(piVar7 + 0x14) = 0;
  *(undefined2 *)((int)piVar7 + 0x4e) = 0;
  *(undefined2 *)(piVar7 + 0x13) = 0;
  FUN_8003842c(uVar4,0xc,piVar7 + 0x16,piVar7 + 0x17,piVar7 + 0x18,1);
  uVar4 = FUN_800383a0(uVar4,0);
  FUN_80003494(piVar7 + 0x19,uVar4,0x30);
  fVar1 = FLOAT_803e4bd8;
  piVar7[0x1c] = (int)FLOAT_803e4bd8;
  piVar7[0x20] = (int)fVar1;
  piVar7[0x24] = (int)fVar1;
  DAT_803ddb80 = DAT_803ddb80 & 0xffffe1ef;
  __psq_l0(auStack8,uVar8);
  __psq_l1(auStack8,uVar8);
  __psq_l0(auStack24,uVar8);
  __psq_l1(auStack24,uVar8);
  __psq_l0(auStack40,uVar8);
  __psq_l1(auStack40,uVar8);
  __psq_l0(auStack56,uVar8);
  __psq_l1(auStack56,uVar8);
  FUN_8028610c();
  return;
}

