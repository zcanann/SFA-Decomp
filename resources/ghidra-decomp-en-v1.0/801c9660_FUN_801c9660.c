// Function: FUN_801c9660
// Entry: 801c9660
// Size: 1492 bytes

/* WARNING: Removing unreachable block (ram,0x801c9c0c) */
/* WARNING: Removing unreachable block (ram,0x801c9bfc) */
/* WARNING: Removing unreachable block (ram,0x801c9c04) */
/* WARNING: Removing unreachable block (ram,0x801c9c14) */

void FUN_801c9660(undefined4 param_1,undefined4 param_2,int param_3)

{
  float fVar1;
  int iVar2;
  int iVar3;
  int iVar4;
  uint uVar5;
  int *piVar6;
  int iVar7;
  undefined4 uVar8;
  undefined8 in_f28;
  double dVar9;
  undefined8 in_f29;
  double dVar10;
  undefined8 in_f30;
  double dVar11;
  undefined8 in_f31;
  double dVar12;
  int local_78;
  int local_74;
  undefined4 local_70;
  uint uStack108;
  double local_68;
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
  iVar2 = FUN_802860d8();
  piVar6 = *(int **)(iVar2 + 0xb8);
  iVar3 = FUN_8002b9ec();
  FUN_8000b99c((double)FLOAT_803e50e0,iVar2,0x3af,10);
  FUN_8000da58(iVar2,0x3af);
  *(undefined *)(param_3 + 0x56) = 0;
  for (iVar7 = 0; iVar7 < (int)(uint)*(byte *)(param_3 + 0x8b); iVar7 = iVar7 + 1) {
    if (*(char *)(param_3 + iVar7 + 0x81) == '\x01') {
      FUN_800146bc(0x1d,0x3c);
      FUN_8001469c();
      *(byte *)(piVar6 + 8) = *(byte *)(piVar6 + 8) & 0xbf;
      *(uint *)(*(int *)(iVar2 + 100) + 0x30) = *(uint *)(*(int *)(iVar2 + 100) + 0x30) | 4;
    }
  }
  if ((*(byte *)(piVar6 + 8) >> 6 & 1) == 0) {
    if (*piVar6 == 0) {
      iVar7 = FUN_8002e0fc(&local_74,&local_78);
      while ((local_74 < local_78 &&
             (*piVar6 = *(int *)(iVar7 + local_74 * 4), *(short *)(*piVar6 + 0x46) != 0x20f))) {
        local_74 = local_74 + 1;
      }
    }
    if (*piVar6 != 0) {
      dVar10 = (double)FLOAT_803e50e8;
      dVar12 = (double)FLOAT_803e50f8;
      dVar9 = (double)FLOAT_803e5100;
      dVar11 = DOUBLE_803e5110;
      for (iVar7 = 0; iVar7 < (int)(uint)DAT_803db410; iVar7 = iVar7 + 1) {
        iVar4 = FUN_80014670();
        if (iVar4 != 0) {
          FUN_8000bb18(iVar2,0x1d4);
          *(byte *)(piVar6 + 8) = *(byte *)(piVar6 + 8) & 0x7f;
          *(byte *)(piVar6 + 8) = *(byte *)(piVar6 + 8) & 0xbf | 0x40;
          (**(code **)(*DAT_803dca54 + 0x58))(param_3,0xbd);
        }
        uVar5 = FUN_80014e14(0);
        if ((uVar5 & 0x100) != 0) {
          piVar6[1] = (int)((float)piVar6[1] + FLOAT_803e50e4);
        }
        if (dVar10 < (double)(float)piVar6[1]) {
          piVar6[1] = (int)(float)dVar10;
        }
        uStack108 = piVar6[4] ^ 0x80000000;
        local_70 = 0x43300000;
        iVar4 = (int)((float)((double)CONCAT44(0x43300000,uStack108) - dVar11) + (float)piVar6[1]);
        local_68 = (double)(longlong)iVar4;
        piVar6[4] = iVar4;
        if (0x7ef3 < piVar6[4]) {
          FUN_8001467c();
          FUN_8000bb18(iVar2,0x1d4);
          FUN_80030334((double)FLOAT_803e50ec,iVar3,0,0);
          *(byte *)(piVar6 + 8) = *(byte *)(piVar6 + 8) & 0x7f | 0x80;
          *(byte *)(piVar6 + 8) = *(byte *)(piVar6 + 8) & 0xbf | 0x40;
          piVar6[4] = 0x7ef4;
          (**(code **)(*DAT_803dca54 + 0x58))(param_3,0xbd);
          goto LAB_801c9bfc;
        }
        (**(code **)(*DAT_803dca54 + 0x74))(piVar6[6]);
        if (piVar6[4] < 0) {
          piVar6[4] = 0;
          if ((float)piVar6[1] < FLOAT_803e50ec) {
            piVar6[1] = (int)FLOAT_803e50ec;
          }
          piVar6[5] = piVar6[4];
          if (FLOAT_803e50f0 < (float)piVar6[1]) {
            piVar6[1] = (int)((float)piVar6[1] - FLOAT_803e50f4);
          }
          goto LAB_801c9bfc;
        }
        if (dVar12 < (double)(float)piVar6[1]) {
          piVar6[1] = (int)(float)((double)(float)piVar6[1] - (double)FLOAT_803e50fc);
        }
        local_68 = (double)CONCAT44(0x43300000,piVar6[4] ^ 0x80000000);
        uStack108 = piVar6[5] ^ 0x80000000;
        local_70 = 0x43300000;
        iVar4 = FUN_8002fa48((double)(float)((double)((float)(local_68 - dVar11) -
                                                     (float)((double)CONCAT44(0x43300000,uStack108)
                                                            - dVar11)) / dVar9),
                             (double)FLOAT_803db414,iVar3,0);
        if ((iVar4 != 0) && (*(float *)(iVar3 + 0x98) < FLOAT_803e50ec)) {
          *(float *)(iVar3 + 0x98) = FLOAT_803e5104 + *(float *)(iVar3 + 0x98);
        }
        if (*piVar6 != 0) {
          local_68 = (double)CONCAT44(0x43300000,piVar6[4] ^ 0x80000000);
          uStack108 = piVar6[5] ^ 0x80000000;
          local_70 = 0x43300000;
          iVar4 = FUN_8002fa48((double)(-((float)(local_68 - DOUBLE_803e5110) -
                                         (float)((double)CONCAT44(0x43300000,uStack108) -
                                                DOUBLE_803e5110)) / FLOAT_803e5100),
                               (double)FLOAT_803db414,*piVar6,0);
          if (iVar4 != 0) {
            fVar1 = *(float *)(*piVar6 + 0x98);
            if (fVar1 < FLOAT_803e50ec) {
              *(float *)(*piVar6 + 0x98) = FLOAT_803e5104 + fVar1;
            }
          }
        }
        piVar6[5] = piVar6[4];
      }
      piVar6[3] = (int)((float)piVar6[3] - FLOAT_803db414);
      if ((float)piVar6[3] < FLOAT_803e50ec) {
        if (FLOAT_803e50ec <= (float)piVar6[1]) {
          uVar5 = FUN_800221a0(0x78,0xf0);
          local_68 = (double)CONCAT44(0x43300000,uVar5 ^ 0x80000000);
          piVar6[3] = (int)(float)(local_68 - DOUBLE_803e5110);
        }
        else {
          uVar5 = FUN_800221a0(0x28,100);
          local_68 = (double)CONCAT44(0x43300000,uVar5 ^ 0x80000000);
          piVar6[3] = (int)(float)(local_68 - DOUBLE_803e5110);
        }
        FUN_8000bb18(iVar3,0x13a);
      }
      piVar6[2] = (int)((float)piVar6[2] - FLOAT_803db414);
      if ((float)piVar6[2] < FLOAT_803e50ec) {
        if ((float)piVar6[1] <= FLOAT_803e50ec) {
          uVar5 = FUN_800221a0(0x78,0xf0);
          local_68 = (double)CONCAT44(0x43300000,uVar5 ^ 0x80000000);
          piVar6[2] = (int)(float)(local_68 - DOUBLE_803e5110);
        }
        else {
          uVar5 = FUN_800221a0(0x28,100);
          local_68 = (double)CONCAT44(0x43300000,uVar5 ^ 0x80000000);
          piVar6[2] = (int)(float)(local_68 - DOUBLE_803e5110);
        }
        FUN_8000bb18(iVar2,0x4a3);
      }
      fVar1 = FLOAT_803e5108 * (float)piVar6[1];
      if (fVar1 < FLOAT_803e50ec) {
        fVar1 = -fVar1;
      }
      uVar5 = (uint)fVar1;
      local_68 = (double)(longlong)(int)uVar5;
      if (100 < (int)uVar5) {
        uVar5 = 100;
      }
      FUN_8000b99c((double)FLOAT_803e50e0,iVar2,0x3af,uVar5 & 0xff);
    }
  }
LAB_801c9bfc:
  __psq_l0(auStack8,uVar8);
  __psq_l1(auStack8,uVar8);
  __psq_l0(auStack24,uVar8);
  __psq_l1(auStack24,uVar8);
  __psq_l0(auStack40,uVar8);
  __psq_l1(auStack40,uVar8);
  __psq_l0(auStack56,uVar8);
  __psq_l1(auStack56,uVar8);
  FUN_80286124(0);
  return;
}

