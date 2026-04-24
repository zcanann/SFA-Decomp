// Function: FUN_801a1230
// Entry: 801a1230
// Size: 708 bytes

/* WARNING: Removing unreachable block (ram,0x801a14cc) */
/* WARNING: Removing unreachable block (ram,0x801a14c4) */
/* WARNING: Removing unreachable block (ram,0x801a14d4) */

void FUN_801a1230(void)

{
  int iVar1;
  int iVar2;
  undefined4 *puVar3;
  int iVar4;
  undefined4 *puVar5;
  int iVar6;
  int iVar7;
  int iVar8;
  undefined4 uVar9;
  undefined8 in_f29;
  double dVar10;
  undefined8 in_f30;
  double dVar11;
  undefined8 in_f31;
  double dVar12;
  int local_58;
  undefined auStack84 [44];
  undefined auStack40 [16];
  undefined auStack24 [16];
  undefined auStack8 [8];
  
  uVar9 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  __psq_st0(auStack24,(int)((ulonglong)in_f30 >> 0x20),0);
  __psq_st1(auStack24,(int)in_f30,0);
  __psq_st0(auStack40,(int)((ulonglong)in_f29 >> 0x20),0);
  __psq_st1(auStack40,(int)in_f29,0);
  iVar1 = FUN_802860d4();
  iVar8 = *(int *)(iVar1 + 0xb8);
  iVar2 = FUN_8003687c(iVar1,auStack84,0,0);
  if ((iVar2 != 0) ||
     ((*(char *)(*(int *)(iVar1 + 0x54) + 0xad) != '\0' && ((*(byte *)(iVar8 + 0x49) & 2) != 0)))) {
    *(char *)(iVar8 + 0x16) = *(char *)(iVar8 + 0x16) + '\x01';
    *(byte *)(iVar8 + 0x49) = *(byte *)(iVar8 + 0x49) | 1;
  }
  if (*(char *)(iVar8 + 0x16) != '\0') {
    if ((*(byte *)(iVar8 + 0x48) >> 6 & 1) != 0) {
      iVar6 = *(int *)(iVar1 + 0x4c);
      iVar2 = 0;
      if (*(short *)(iVar6 + 0x1a) == 0) {
        iVar2 = FUN_80036e58(0x3a,iVar1,0);
      }
      else {
        puVar3 = (undefined4 *)FUN_80036f50(0x3a,&local_58);
        puVar5 = puVar3;
        for (iVar7 = 0; iVar7 < local_58; iVar7 = iVar7 + 1) {
          iVar4 = FUN_80221670(*puVar5);
          if (*(short *)(iVar6 + 0x1a) == iVar4) {
            iVar2 = puVar3[iVar7];
            break;
          }
          puVar5 = puVar5 + 1;
        }
      }
      if (iVar2 != 0) {
        dVar12 = (double)*(float *)(iVar1 + 0xc);
        dVar11 = (double)*(float *)(iVar1 + 0x10);
        dVar10 = (double)*(float *)(iVar1 + 0x14);
        *(undefined4 *)(iVar1 + 0xc) = *(undefined4 *)(iVar2 + 0xc);
        *(undefined4 *)(iVar1 + 0x10) = *(undefined4 *)(iVar2 + 0x10);
        *(undefined4 *)(iVar1 + 0x14) = *(undefined4 *)(iVar2 + 0x14);
        FUN_800e8370(iVar1);
        *(float *)(iVar1 + 0xc) = (float)dVar12;
        *(float *)(iVar1 + 0x10) = (float)dVar11;
        *(float *)(iVar1 + 0x14) = (float)dVar10;
      }
    }
    FUN_80035e5c(iVar1,0x80);
    FUN_80035e48(iVar1,1);
    FUN_80035b50(iVar1,0x14,0xfffffffb,0x14);
    FUN_80035f20(iVar1);
    FUN_80035df4(iVar1,5,4,0);
    FUN_8000bb18(iVar1,0xd1);
    *(float *)(iVar1 + 0x10) = *(float *)(iVar1 + 0x10) + FLOAT_803e4308;
    FUN_8009ab70((double)FLOAT_803e42c0,iVar1,1,1,0,0,0,1,0);
    if (*(char *)(iVar8 + 0x15) != '\0') {
      (**(code **)(*DAT_803dcac0 + 0x30))(iVar1,iVar8);
      *(undefined *)(iVar8 + 0x15) = 0;
    }
    *(undefined *)(iVar8 + 0x17) = 1;
    *(byte *)(iVar8 + 0x4a) = *(byte *)(iVar8 + 0x4a) & 0xdf;
    FUN_80036fa4(iVar1,0x19);
    if (*(int *)(iVar1 + 0x30) == 0) {
      *(float *)(iVar8 + 0x34) = FLOAT_803e42c4;
    }
    else {
      *(float *)(iVar8 + 0x34) = FLOAT_803e42c4;
    }
    iVar1 = FUN_8002b9ac();
    if (iVar1 != 0) {
      FUN_80138ef8();
    }
    *(byte *)(iVar8 + 0x49) = *(byte *)(iVar8 + 0x49) & 0xfd;
    if (*(int *)(iVar8 + 0x10) != 0) {
      FUN_802385c8();
    }
  }
  __psq_l0(auStack8,uVar9);
  __psq_l1(auStack8,uVar9);
  __psq_l0(auStack24,uVar9);
  __psq_l1(auStack24,uVar9);
  __psq_l0(auStack40,uVar9);
  __psq_l1(auStack40,uVar9);
  FUN_80286120();
  return;
}

