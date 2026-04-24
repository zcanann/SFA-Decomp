// Function: FUN_801ef3a8
// Entry: 801ef3a8
// Size: 2956 bytes

/* WARNING: Removing unreachable block (ram,0x801eff0c) */
/* WARNING: Removing unreachable block (ram,0x801eff04) */
/* WARNING: Removing unreachable block (ram,0x801eff14) */

void FUN_801ef3a8(void)

{
  bool bVar1;
  undefined2 *puVar2;
  char cVar6;
  int *piVar3;
  undefined uVar7;
  short sVar5;
  int iVar4;
  short *psVar8;
  int iVar9;
  undefined4 uVar10;
  undefined8 in_f29;
  double dVar11;
  undefined8 in_f30;
  double dVar12;
  undefined8 in_f31;
  double dVar13;
  int local_88;
  undefined2 local_84;
  undefined2 local_82;
  undefined2 local_80;
  float local_7c;
  float local_78;
  float local_74;
  float local_70;
  undefined4 local_68;
  uint uStack100;
  undefined4 local_60;
  uint uStack92;
  undefined4 local_58;
  uint uStack84;
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
  puVar2 = (undefined2 *)FUN_802860dc();
  iVar9 = *(int *)(puVar2 + 0x26);
  psVar8 = *(short **)(puVar2 + 0x5c);
  cVar6 = FUN_8002e04c();
  if (cVar6 != '\0') {
    switch(*(undefined2 *)(iVar9 + 0x1a)) {
    case 0:
      bVar1 = false;
      if (*(int *)(puVar2 + 0x7c) == 0) {
        iVar4 = FUN_8001ffb4(0x78);
        bVar1 = iVar4 == 0;
        piVar3 = (int *)FUN_80036f50(3,&local_88);
        iVar4 = 0;
        while ((iVar4 < local_88 && (bVar1))) {
          if (*(short *)(*piVar3 + 0x46) == 0x139) {
            bVar1 = false;
          }
          piVar3 = piVar3 + 1;
          iVar4 = iVar4 + 1;
        }
      }
      if (bVar1) {
        iVar4 = FUN_8002bdf4(0x24,0x139);
        *(undefined4 *)(iVar4 + 8) = *(undefined4 *)(iVar9 + 8);
        *(undefined4 *)(iVar4 + 0xc) = *(undefined4 *)(iVar9 + 0xc);
        *(undefined4 *)(iVar4 + 0x10) = *(undefined4 *)(iVar9 + 0x10);
        *(undefined *)(iVar4 + 4) = *(undefined *)(iVar9 + 4);
        *(undefined *)(iVar4 + 5) = *(undefined *)(iVar9 + 5);
        *(undefined *)(iVar4 + 6) = *(undefined *)(iVar9 + 6);
        *(undefined *)(iVar4 + 7) = *(undefined *)(iVar9 + 7);
        *(undefined2 *)(iVar4 + 0x1e) = 0xffff;
        *(undefined2 *)(iVar4 + 0x1a) = 2;
        *(undefined *)(iVar4 + 0x18) = *(undefined *)(iVar9 + 0x1e);
        iVar9 = FUN_8002df90(iVar4,5,(int)*(char *)(puVar2 + 0x56),0xffffffff,
                             *(undefined4 *)(puVar2 + 0x18));
        if (iVar9 != 0) {
          *(undefined4 *)(iVar9 + 0xf4) = 8;
        }
        *(undefined4 *)(puVar2 + 0x7c) = 1;
      }
      break;
    case 1:
      iVar9 = FUN_8001ffb4((int)*psVar8);
      if (((iVar9 != 0) || (*psVar8 == -1)) &&
         (psVar8[2] = psVar8[2] - (ushort)DAT_803db410, psVar8[2] < 1)) {
        iVar9 = FUN_8002bdf4(0x28,0x263);
        *(undefined *)(iVar9 + 4) = 0x20;
        *(undefined *)(iVar9 + 5) = 2;
        *(undefined *)(iVar9 + 7) = 0xff;
        *(undefined4 *)(iVar9 + 8) = *(undefined4 *)(puVar2 + 6);
        *(undefined4 *)(iVar9 + 0xc) = *(undefined4 *)(puVar2 + 8);
        *(undefined4 *)(iVar9 + 0x10) = *(undefined4 *)(puVar2 + 10);
        *(undefined2 *)(iVar9 + 0x20) = 0x50;
        *(undefined2 *)(iVar9 + 0x1e) = 0x10f;
        *(undefined2 *)(iVar9 + 0x22) = 0xffff;
        sVar5 = FUN_800221a0(0xfffffe0c,500);
        *(short *)(iVar9 + 0x18) = sVar5 + 0x5dc;
        *(undefined2 *)(iVar9 + 0x1a) = 0;
        sVar5 = FUN_800221a0(0xfffffe0c,500);
        *(short *)(iVar9 + 0x1c) = sVar5 + 0x5dc;
        iVar9 = FUN_8002df90(iVar9,5,(int)*(char *)(puVar2 + 0x56),0xffffffff,
                             *(undefined4 *)(puVar2 + 0x18));
        if (iVar9 != 0) {
          uStack100 = FUN_800221a0(0,10);
          uStack100 = uStack100 ^ 0x80000000;
          local_68 = 0x43300000;
          *(float *)(iVar9 + 0x24) =
               FLOAT_803e5ccc + (float)((double)CONCAT44(0x43300000,uStack100) - DOUBLE_803e5ce0);
        }
        sVar5 = FUN_800221a0(0,(int)psVar8[3]);
        psVar8[2] = psVar8[1] + sVar5;
      }
      break;
    case 2:
      iVar4 = FUN_8001ffb4((int)*psVar8);
      if (((iVar4 != 0) || (*psVar8 == -1)) &&
         (psVar8[2] = psVar8[2] - (ushort)DAT_803db410, psVar8[2] < 1)) {
        iVar4 = FUN_8002bdf4(0x28,0x263);
        *(undefined *)(iVar4 + 4) = 4;
        *(undefined *)(iVar4 + 5) = 2;
        *(undefined4 *)(iVar4 + 8) = *(undefined4 *)(iVar9 + 8);
        uStack92 = FUN_800221a0(0xffffffd8,0x28);
        uStack92 = uStack92 ^ 0x80000000;
        local_60 = 0x43300000;
        *(float *)(iVar4 + 0xc) =
             *(float *)(iVar9 + 0xc) +
             (float)((double)CONCAT44(0x43300000,uStack92) - DOUBLE_803e5ce0);
        uStack100 = FUN_800221a0(0xffffffd8,0x28);
        uStack100 = uStack100 ^ 0x80000000;
        local_68 = 0x43300000;
        *(float *)(iVar4 + 0x10) =
             *(float *)(iVar9 + 0x10) +
             (float)((double)CONCAT44(0x43300000,uStack100) - DOUBLE_803e5ce0);
        *(undefined2 *)(iVar4 + 0x20) = 100;
        *(undefined2 *)(iVar4 + 0x1e) = 0x10f;
        *(undefined2 *)(iVar4 + 0x22) = 0xffff;
        sVar5 = FUN_800221a0(0xfffffe0c,500);
        *(short *)(iVar4 + 0x18) = sVar5 + 0x5dc;
        sVar5 = FUN_800221a0(0xfffffe0c,500);
        *(short *)(iVar4 + 0x1c) = sVar5 + 0x5dc;
        iVar9 = FUN_8002df90(iVar4,5,(int)*(char *)(puVar2 + 0x56),0xffffffff,
                             *(undefined4 *)(puVar2 + 0x18));
        if (iVar9 != 0) {
          uStack92 = FUN_800221a0(0,10);
          uStack92 = uStack92 ^ 0x80000000;
          local_60 = 0x43300000;
          *(float *)(iVar9 + 0x24) =
               FLOAT_803e5cd0 - (float)((double)CONCAT44(0x43300000,uStack92) - DOUBLE_803e5ce0);
        }
        sVar5 = FUN_800221a0(0,(int)psVar8[3]);
        psVar8[2] = psVar8[1] + sVar5;
      }
      break;
    case 4:
      iVar9 = FUN_8001ffb4((int)*psVar8);
      if ((iVar9 != 0) || (*psVar8 == -1)) {
        iVar9 = 2;
        do {
          iVar9 = iVar9 + -1;
          iVar4 = FUN_8002bdf4(0x28,0x263);
          *(undefined *)(iVar4 + 4) = 0x20;
          *(undefined *)(iVar4 + 5) = 2;
          *(undefined *)(iVar4 + 7) = 0xff;
          *(undefined4 *)(iVar4 + 8) = *(undefined4 *)(puVar2 + 6);
          *(undefined4 *)(iVar4 + 0xc) = *(undefined4 *)(puVar2 + 8);
          *(undefined4 *)(iVar4 + 0x10) = *(undefined4 *)(puVar2 + 10);
          *(undefined2 *)(iVar4 + 0x20) = 400;
          *(undefined2 *)(iVar4 + 0x1e) = 0xf;
          *(undefined2 *)(iVar4 + 0x22) = 0x222;
          *(undefined2 *)(iVar4 + 0x18) = 0;
          *(undefined2 *)(iVar4 + 0x1a) = 0;
          *(undefined2 *)(iVar4 + 0x1c) = 0;
          *(undefined *)(iVar4 + 0x24) = 0;
          iVar4 = FUN_8002df90(iVar4,5,(int)*(char *)(puVar2 + 0x56),0xffffffff,
                               *(undefined4 *)(puVar2 + 0x18));
          if (iVar4 != 0) {
            *(byte *)(*(int *)(iVar4 + 0xb8) + 0x120) =
                 *(byte *)(*(int *)(iVar4 + 0xb8) + 0x120) | 2;
            uStack92 = FUN_800221a0(0xffffffdd,0x23);
            uStack92 = uStack92 ^ 0x80000000;
            local_60 = 0x43300000;
            *(float *)(iVar4 + 0x24) =
                 FLOAT_803e5cd4 * (float)((double)CONCAT44(0x43300000,uStack92) - DOUBLE_803e5ce0);
            uStack100 = FUN_800221a0(0xffffffdd,0x23);
            uStack100 = uStack100 ^ 0x80000000;
            local_68 = 0x43300000;
            *(float *)(iVar4 + 0x2c) =
                 FLOAT_803e5cd4 * (float)((double)CONCAT44(0x43300000,uStack100) - DOUBLE_803e5ce0);
            local_74 = FLOAT_803e5cd8;
            *(float *)(iVar4 + 0x28) = FLOAT_803e5cd8;
            local_7c = FLOAT_803e5cc8;
            local_84 = 0;
            local_82 = 0;
            local_80 = 0;
            local_78 = *(float *)(iVar4 + 0x24);
            local_70 = *(float *)(iVar4 + 0x2c);
            (**(code **)(*DAT_803dca88 + 8))(iVar4,0x1a7,&local_84,0x10000,0xffffffff,0);
          }
        } while (iVar9 != 0);
        FUN_800200e8((int)*psVar8,0);
      }
      break;
    case 5:
      iVar9 = FUN_8001ffb4((int)*psVar8);
      if (((iVar9 != 0) || (*psVar8 == -1)) &&
         (psVar8[2] = psVar8[2] - (ushort)DAT_803db410, psVar8[2] < 1)) {
        iVar9 = FUN_8002bdf4(0x24,0x275);
        uVar7 = FUN_800221a0(0xffffff81,0x7e);
        *(undefined *)(iVar9 + 0x18) = uVar7;
        uStack100 = FUN_800221a0(0xffffff9c,100);
        uStack100 = uStack100 ^ 0x80000000;
        local_68 = 0x43300000;
        *(float *)(iVar9 + 8) =
             *(float *)(puVar2 + 6) +
             (float)((double)CONCAT44(0x43300000,uStack100) - DOUBLE_803e5ce0);
        *(undefined4 *)(iVar9 + 0xc) = *(undefined4 *)(puVar2 + 8);
        uStack92 = FUN_800221a0(0xffffff9c,100);
        uStack92 = uStack92 ^ 0x80000000;
        local_60 = 0x43300000;
        *(float *)(iVar9 + 0x10) =
             *(float *)(puVar2 + 10) +
             (float)((double)CONCAT44(0x43300000,uStack92) - DOUBLE_803e5ce0);
        *(undefined2 *)(iVar9 + 0x1a) = 0x31;
        *(undefined2 *)(iVar9 + 0x1c) = 200;
        iVar9 = FUN_8002df90(iVar9,5,(int)*(char *)(puVar2 + 0x56),0xffffffff,
                             *(undefined4 *)(puVar2 + 0x18));
        if (iVar9 != 0) {
          DAT_803ddc68 = DAT_803ddc68 + 1;
        }
        sVar5 = FUN_800221a0(0,(int)psVar8[3]);
        psVar8[2] = psVar8[1] + sVar5;
      }
      break;
    case 6:
      iVar9 = FUN_8001ffb4((int)*psVar8);
      if ((iVar9 != 0) || (*psVar8 == -1)) {
        iVar9 = FUN_8002bdf4(0x24,700);
        uStack84 = FUN_800221a0(0xfffffefc,0x104);
        uStack84 = uStack84 ^ 0x80000000;
        local_58 = 0x43300000;
        *(float *)(iVar9 + 8) =
             *(float *)(puVar2 + 6) +
             (float)((double)CONCAT44(0x43300000,uStack84) - DOUBLE_803e5ce0);
        *(float *)(iVar9 + 0xc) = FLOAT_803e5cdc + *(float *)(puVar2 + 8);
        uStack92 = FUN_800221a0(0xffffffb0,0x50);
        uStack92 = uStack92 ^ 0x80000000;
        local_60 = 0x43300000;
        *(float *)(iVar9 + 0x10) =
             *(float *)(puVar2 + 10) +
             (float)((double)CONCAT44(0x43300000,uStack92) - DOUBLE_803e5ce0);
        *(undefined *)(iVar9 + 4) = 0x20;
        *(undefined *)(iVar9 + 5) = 2;
        *(undefined *)(iVar9 + 7) = 0xff;
        *(undefined2 *)(iVar9 + 0x1e) = 0xffff;
        *(char *)(iVar9 + 0x18) = (char)((ushort)*puVar2 >> 8);
        FUN_8002df90(iVar9,5,(int)*(char *)(puVar2 + 0x56),0xffffffff,*(undefined4 *)(puVar2 + 0x18)
                    );
        iVar9 = FUN_800221a0(2,5);
        dVar11 = (double)FLOAT_803e5cc8;
        dVar13 = (double)FLOAT_803e5cdc;
        dVar12 = DOUBLE_803e5ce0;
        for (; iVar9 != 0; iVar9 = iVar9 + -1) {
          local_7c = (float)dVar11;
          local_84 = 0;
          local_82 = 0;
          local_80 = 0;
          uStack84 = FUN_800221a0(0xffffff38,200);
          uStack84 = uStack84 ^ 0x80000000;
          local_58 = 0x43300000;
          local_78 = (float)((double)CONCAT44(0x43300000,uStack84) - dVar12);
          uStack92 = FUN_800221a0(0xffffffec,0x14);
          uStack92 = uStack92 ^ 0x80000000;
          local_60 = 0x43300000;
          local_70 = (float)((double)CONCAT44(0x43300000,uStack92) - dVar12);
          local_74 = (float)dVar13;
          (**(code **)(*DAT_803dca88 + 8))(puVar2,0x1a6,&local_84,0x10002,0xffffffff,0);
        }
        FUN_800200e8((int)*psVar8,0);
      }
      break;
    case 7:
      iVar4 = FUN_8001ffb4((int)*psVar8);
      if (((iVar4 != 0) || (*psVar8 == -1)) &&
         (psVar8[2] = psVar8[2] - (ushort)DAT_803db410, psVar8[2] < 1)) {
        iVar4 = FUN_8002bdf4(0x28,0x263);
        *(undefined *)(iVar4 + 4) = 4;
        *(undefined *)(iVar4 + 5) = 2;
        uStack92 = FUN_800221a0(0xffffffd8,0x28);
        uStack92 = uStack92 ^ 0x80000000;
        local_60 = 0x43300000;
        *(float *)(iVar4 + 8) =
             *(float *)(iVar9 + 8) +
             (float)((double)CONCAT44(0x43300000,uStack92) - DOUBLE_803e5ce0);
        uStack100 = FUN_800221a0(0,0x14);
        uStack100 = uStack100 ^ 0x80000000;
        local_68 = 0x43300000;
        *(float *)(iVar4 + 0xc) =
             *(float *)(iVar9 + 0xc) +
             (float)((double)CONCAT44(0x43300000,uStack100) - DOUBLE_803e5ce0);
        uStack84 = FUN_800221a0(0xffffffd8,0x28);
        uStack84 = uStack84 ^ 0x80000000;
        local_58 = 0x43300000;
        *(float *)(iVar4 + 0x10) =
             *(float *)(iVar9 + 0x10) +
             (float)((double)CONCAT44(0x43300000,uStack84) - DOUBLE_803e5ce0);
        *(undefined2 *)(iVar4 + 0x20) = 0x1c2;
        sVar5 = FUN_800221a0(0,2);
        *(short *)(iVar4 + 0x1e) = sVar5 + 0x1cc;
        *(undefined2 *)(iVar4 + 0x22) = 0xffff;
        sVar5 = FUN_800221a0(0xfffffe0c,500);
        *(short *)(iVar4 + 0x18) = sVar5 + 0x5dc;
        sVar5 = FUN_800221a0(0xfffffe0c,500);
        *(short *)(iVar4 + 0x1c) = sVar5 + 0x5dc;
        FUN_8002df90(iVar4,5,(int)*(char *)(puVar2 + 0x56),0xffffffff,*(undefined4 *)(puVar2 + 0x18)
                    );
        sVar5 = FUN_800221a0(0,(int)psVar8[3]);
        psVar8[2] = psVar8[1] + sVar5;
      }
      break;
    case 8:
      iVar9 = FUN_8001ffb4((int)*psVar8);
      if (((iVar9 != 0) || (*psVar8 == -1)) &&
         (psVar8[2] = psVar8[2] - (ushort)DAT_803db410, psVar8[2] < 1)) {
        iVar9 = FUN_8002bdf4(0x38,0x4ac);
        FUN_800200e8((int)*psVar8,0);
        uVar7 = FUN_800221a0(0xffffff81,0x7e);
        *(undefined *)(iVar9 + 0x2a) = uVar7;
        *(undefined4 *)(iVar9 + 8) = *(undefined4 *)(puVar2 + 6);
        *(undefined4 *)(iVar9 + 0xc) = *(undefined4 *)(puVar2 + 8);
        *(undefined4 *)(iVar9 + 0x10) = *(undefined4 *)(puVar2 + 10);
        *(short *)(iVar9 + 0x18) = *psVar8;
        *(undefined2 *)(iVar9 + 0x22) = 1;
        iVar9 = FUN_8002df90(iVar9,5,(int)*(char *)(puVar2 + 0x56),0xffffffff,
                             *(undefined4 *)(puVar2 + 0x18));
        if (iVar9 != 0) {
          (**(code **)(*DAT_803dca88 + 8))(puVar2,0x1c3,0,2,0xffffffff,0);
        }
        sVar5 = FUN_800221a0(0,(int)psVar8[3]);
        psVar8[2] = psVar8[1] + sVar5;
      }
    }
  }
  __psq_l0(auStack8,uVar10);
  __psq_l1(auStack8,uVar10);
  __psq_l0(auStack24,uVar10);
  __psq_l1(auStack24,uVar10);
  __psq_l0(auStack40,uVar10);
  __psq_l1(auStack40,uVar10);
  FUN_80286128();
  return;
}

