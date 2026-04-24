// Function: FUN_801e34c0
// Entry: 801e34c0
// Size: 2132 bytes

/* WARNING: Removing unreachable block (ram,0x801e3cec) */
/* WARNING: Removing unreachable block (ram,0x801e3ce4) */
/* WARNING: Removing unreachable block (ram,0x801e3cf4) */

void FUN_801e34c0(void)

{
  float fVar1;
  int iVar2;
  int iVar3;
  int iVar4;
  int iVar5;
  int iVar6;
  uint uVar7;
  undefined2 uVar9;
  char cVar11;
  undefined2 *puVar8;
  short sVar10;
  int *piVar12;
  int iVar13;
  undefined4 uVar14;
  undefined8 uVar15;
  double dVar16;
  undefined8 in_f29;
  undefined8 in_f30;
  double dVar17;
  undefined8 in_f31;
  double dVar18;
  double dVar19;
  int local_88;
  int local_84;
  undefined4 local_80;
  undefined4 local_7c;
  float local_78;
  float local_74;
  float local_70;
  float local_6c;
  undefined2 local_68;
  undefined2 local_66;
  undefined2 local_64;
  undefined2 local_62;
  float local_60;
  float local_5c;
  float local_58;
  float local_54 [11];
  undefined auStack40 [16];
  undefined auStack24 [16];
  undefined auStack8 [8];
  
  uVar14 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  __psq_st0(auStack24,(int)((ulonglong)in_f30 >> 0x20),0);
  __psq_st1(auStack24,(int)in_f30,0);
  __psq_st0(auStack40,(int)((ulonglong)in_f29 >> 0x20),0);
  __psq_st1(auStack40,(int)in_f29,0);
  iVar2 = FUN_802860d8();
  iVar3 = FUN_8002b9ec();
  piVar12 = *(int **)(iVar2 + 0xb8);
  iVar13 = *(int *)(iVar2 + 0x4c);
  if (*(short *)(*(int *)(iVar2 + 0x30) + 0x46) == 0x139) {
    *(ushort *)(*(int *)(iVar2 + 0x54) + 0x60) = *(ushort *)(*(int *)(iVar2 + 0x54) + 0x60) & 0xfffe
    ;
    *(undefined *)((int)piVar12 + 0xd) = 0;
  }
  else {
    if (*piVar12 == 0) {
      iVar4 = FUN_8002e0fc(&local_84,&local_88);
      for (; local_84 < local_88; local_84 = local_84 + 1) {
        iVar5 = *(int *)(iVar4 + local_84 * 4);
        if (*(short *)(iVar5 + 0x46) == 0x8c) {
          *piVar12 = iVar5;
          local_84 = local_88;
        }
      }
    }
    iVar4 = *(int *)(iVar2 + 0x30);
    if ((iVar4 == 0) || (*(short *)(iVar4 + 0x46) != 0x8e)) {
      iVar5 = 0;
      *(undefined *)((int)piVar12 + 10) = 4;
    }
    else {
      iVar5 = (**(code **)(**(int **)(iVar4 + 0x68) + 0x24))(iVar4);
    }
    *(undefined *)((int)piVar12 + 0xd) = 1;
    cVar11 = *(char *)((int)piVar12 + 10);
    if (cVar11 == '\x03') {
      *(ushort *)(*(int *)(iVar2 + 0x54) + 0x60) =
           *(ushort *)(*(int *)(iVar2 + 0x54) + 0x60) & 0xfffe;
      if (*(char *)(piVar12 + 3) == '\0') {
        FUN_8009ab70((double)FLOAT_803e5890,iVar2,1,1,1,0,1,1,0);
        *(undefined *)((int)piVar12 + 10) = 4;
      }
      else {
        *(undefined *)((int)piVar12 + 10) = 5;
      }
    }
    else if (cVar11 < '\x03') {
      if (cVar11 != '\x01') {
        if (cVar11 < '\x01') {
          if (-1 < cVar11) {
            if ((iVar4 != 0) &&
               (iVar4 = (**(code **)(**(int **)(iVar4 + 0x68) + 0x28))(iVar4), iVar4 == 0)) {
              if (*(char *)(iVar13 + 0x19) == '\0') {
                *(undefined *)((int)piVar12 + 10) = 2;
                *(undefined2 *)(piVar12 + 2) = 0x3c;
              }
              else {
                *(undefined *)((int)piVar12 + 10) = 2;
                *(undefined2 *)(piVar12 + 2) = 0;
              }
            }
            *(ushort *)(*(int *)(iVar2 + 0x54) + 0x60) =
                 *(ushort *)(*(int *)(iVar2 + 0x54) + 0x60) & 0xfffe;
          }
        }
        else {
          *(ushort *)(*(int *)(iVar2 + 0x54) + 0x60) =
               *(ushort *)(*(int *)(iVar2 + 0x54) + 0x60) | 1;
          iVar13 = (**(code **)(**(int **)(iVar4 + 0x68) + 0x28))(iVar4);
          if ((iVar13 == 0) && (iVar6 = FUN_8003687c(iVar2,0,0,0), iVar6 != 0)) {
            FUN_8002ac30(iVar2,0xf,200,0,0,1);
            FUN_8000bb18(iVar2,0x36);
            *(char *)((int)piVar12 + 0xb) = *(char *)((int)piVar12 + 0xb) + '\x01';
            if (*(char *)((int)piVar12 + 0xb) == '\x04') {
              *(char *)(piVar12 + 3) = *(char *)(piVar12 + 3) + -1;
              *(undefined *)((int)piVar12 + 10) = 3;
              if (iVar4 != 0) {
                (**(code **)(**(int **)(iVar4 + 0x68) + 0x20))(iVar4);
              }
            }
            else if (*(char *)((int)piVar12 + 0xb) == '\b') {
              FUN_8000bb18(iVar2,0x3a);
              *(char *)(piVar12 + 3) = *(char *)(piVar12 + 3) + -1;
              *(undefined *)((int)piVar12 + 10) = 3;
              if (iVar4 != 0) {
                (**(code **)(**(int **)(iVar4 + 0x68) + 0x20))(iVar4);
              }
            }
          }
          if ((iVar4 != 0) && (iVar13 != 0)) {
            *(undefined *)((int)piVar12 + 10) = 3;
          }
          dVar16 = (double)(*(float *)(iVar3 + 0x18) - *(float *)(iVar2 + 0x18));
          dVar18 = (double)(*(float *)(iVar3 + 0x20) - *(float *)(iVar2 + 0x20));
          uVar7 = FUN_800217c0(-dVar18,dVar16);
          *(short *)(piVar12 + 1) = (short)((uVar7 & 0xffff) << 1);
          dVar17 = (double)(*(float *)(iVar3 + 0x1c) - *(float *)(iVar2 + 0x1c));
          uVar15 = FUN_802931a0((double)(float)(dVar16 * dVar16 + (double)(float)(dVar18 * dVar18)))
          ;
          uVar9 = FUN_800217c0(-dVar17,uVar15);
          *(undefined2 *)((int)piVar12 + 6) = uVar9;
          if (*(short *)((int)piVar12 + 6) < 0x1f41) {
            if (*(short *)((int)piVar12 + 6) < -8000) {
              *(undefined2 *)((int)piVar12 + 6) = 0xe0c0;
            }
          }
          else {
            *(undefined2 *)((int)piVar12 + 6) = 8000;
          }
          *(ushort *)(piVar12 + 2) = *(short *)(piVar12 + 2) - (ushort)DAT_803db410;
          if ((*(short *)(piVar12 + 2) < 0) && (cVar11 = FUN_8002e04c(), cVar11 != '\0')) {
            FUN_8000e10c(iVar2,&local_78,&local_7c,&local_80);
            local_5c = FLOAT_803e588c;
            local_58 = FLOAT_803e588c;
            local_54[0] = FLOAT_803e588c;
            local_60 = FLOAT_803e5888;
            local_68 = *(undefined2 *)(piVar12 + 1);
            local_66 = 0;
            local_64 = 0;
            local_74 = FLOAT_803e5890;
            local_70 = FLOAT_803e5894;
            local_6c = FLOAT_803e588c;
            FUN_80021ac8(&local_68,&local_74);
            iVar13 = FUN_8002bdf4(0x18,0x113);
            *(float *)(iVar13 + 8) = local_78;
            *(undefined4 *)(iVar13 + 0xc) = local_7c;
            *(undefined4 *)(iVar13 + 0x10) = local_80;
            *(undefined *)(iVar13 + 4) = 2;
            *(undefined *)(iVar13 + 5) = 1;
            *(undefined *)(iVar13 + 6) = 0xff;
            *(undefined *)(iVar13 + 7) = 0xff;
            puVar8 = (undefined2 *)FUN_8002df90(iVar13,5,0xffffffff,0xffffffff,0);
            iVar13 = *piVar12;
            dVar19 = (double)(*(float *)(iVar13 + 0x18) - *(float *)(iVar2 + 0x18));
            dVar17 = (double)(*(float *)(iVar13 + 0x1c) -
                             (*(float *)(iVar2 + 0x1c) - FLOAT_803e5898));
            dVar18 = (double)(*(float *)(iVar13 + 0x20) - *(float *)(iVar2 + 0x20));
            dVar16 = (double)FUN_802931a0((double)(float)(dVar18 * dVar18 +
                                                         (double)(float)(dVar19 * dVar19 +
                                                                        (double)(float)(dVar17 * 
                                                  dVar17))));
            local_78 = FLOAT_803e589c / (float)dVar16;
            *(float *)(puVar8 + 0x12) = (float)(dVar19 * (double)local_78);
            *(float *)(puVar8 + 0x14) = (float)(dVar17 * (double)local_78);
            *(float *)(puVar8 + 0x16) = (float)(dVar18 * (double)local_78);
            fVar1 = FLOAT_803e58a0;
            *(float *)(puVar8 + 6) =
                 FLOAT_803e58a0 * *(float *)(puVar8 + 0x12) + *(float *)(puVar8 + 6);
            *(float *)(puVar8 + 8) = fVar1 * *(float *)(puVar8 + 0x14) + *(float *)(puVar8 + 8);
            *(float *)(puVar8 + 10) = fVar1 * *(float *)(puVar8 + 0x16) + *(float *)(puVar8 + 10);
            uVar9 = FUN_800217c0((double)*(float *)(puVar8 + 0x12),(double)*(float *)(puVar8 + 0x16)
                                );
            *puVar8 = uVar9;
            *(undefined4 *)(puVar8 + 0x7a) = 0x78;
            *(int *)(puVar8 + 0x7c) = *piVar12;
            FUN_8000fad8();
            FUN_8000e67c((double)FLOAT_803e58a4);
            FUN_8000bb18(iVar2,0x3c);
            *(char *)((int)piVar12 + 0xe) = *(char *)((int)piVar12 + 0xe) + '\x01';
            if (*(char *)((int)piVar12 + 0xe) == '\x03') {
              if (iVar5 < 3) {
                sVar10 = FUN_800221a0(0,0x28);
                *(short *)(piVar12 + 2) = sVar10 + 0x78;
              }
              else {
                sVar10 = FUN_800221a0(0,0x28);
                *(short *)(piVar12 + 2) = sVar10 + 0x50;
              }
              *(undefined *)((int)piVar12 + 0xe) = 0;
            }
            else if (iVar5 < 3) {
              *(undefined2 *)(piVar12 + 2) = 0x78;
            }
            else {
              *(undefined2 *)(piVar12 + 2) = 0x50;
            }
          }
        }
      }
    }
    else if (cVar11 == '\x05') {
      *(ushort *)(*(int *)(iVar2 + 0x54) + 0x60) =
           *(ushort *)(*(int *)(iVar2 + 0x54) + 0x60) & 0xfffe;
      if ((iVar4 != 0) &&
         (iVar4 = (**(code **)(**(int **)(iVar4 + 0x68) + 0x28))(iVar4), iVar4 == 0)) {
        if (*(char *)(iVar13 + 0x19) == '\0') {
          if (2 < iVar5) {
            *(undefined *)((int)piVar12 + 10) = 2;
            *(undefined2 *)(piVar12 + 2) = 0x3c;
          }
        }
        else if (2 < iVar5) {
          *(undefined *)((int)piVar12 + 10) = 2;
          *(undefined2 *)(piVar12 + 2) = 0;
        }
      }
      local_60 = FLOAT_803e58a8;
      local_62 = 0xc0a;
      FUN_8003842c(iVar2,0,&local_5c,&local_58,local_54,0);
      local_5c = local_5c - *(float *)(iVar2 + 0x18);
      local_58 = local_58 - *(float *)(iVar2 + 0x1c);
      local_54[0] = local_54[0] - *(float *)(iVar2 + 0x20);
      for (iVar13 = 0; iVar13 < (int)(uint)DAT_803db410; iVar13 = iVar13 + 1) {
        (**(code **)(*DAT_803dca88 + 8))(iVar2,0x7aa,&local_68,2,0xffffffff,0);
      }
    }
    else if (cVar11 < '\x05') {
      local_60 = FLOAT_803e58a8;
      local_62 = 0xc0a;
      FUN_8003842c(iVar2,0,&local_5c,&local_58,local_54,0);
      local_5c = local_5c - *(float *)(iVar2 + 0x18);
      local_58 = local_58 - *(float *)(iVar2 + 0x1c);
      local_54[0] = local_54[0] - *(float *)(iVar2 + 0x20);
      for (iVar13 = 0; iVar13 < (int)(uint)DAT_803db410; iVar13 = iVar13 + 1) {
        (**(code **)(*DAT_803dca88 + 8))(iVar2,0x7aa,&local_68,2,0xffffffff,0);
      }
    }
    if (*(char *)(piVar12 + 3) == '\0') {
      dVar16 = (double)FUN_80021704(iVar3 + 0x18,iVar2 + 0x18);
      if ((double)FLOAT_803e58ac <= dVar16) {
        FUN_8000b7bc(iVar2,0x40);
      }
      else {
        FUN_8000bb18(iVar2,0x312);
      }
    }
  }
  __psq_l0(auStack8,uVar14);
  __psq_l1(auStack8,uVar14);
  __psq_l0(auStack24,uVar14);
  __psq_l1(auStack24,uVar14);
  __psq_l0(auStack40,uVar14);
  __psq_l1(auStack40,uVar14);
  FUN_80286124();
  return;
}

