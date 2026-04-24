// Function: FUN_801a0c14
// Entry: 801a0c14
// Size: 496 bytes

/* WARNING: Removing unreachable block (ram,0x801a0ddc) */
/* WARNING: Removing unreachable block (ram,0x801a0dd4) */
/* WARNING: Removing unreachable block (ram,0x801a0de4) */

void FUN_801a0c14(void)

{
  int iVar1;
  int iVar2;
  undefined4 *puVar3;
  int iVar4;
  int iVar5;
  undefined4 *puVar6;
  int iVar7;
  undefined4 uVar8;
  undefined8 in_f29;
  double dVar9;
  undefined8 in_f30;
  double dVar10;
  undefined8 in_f31;
  double dVar11;
  ulonglong uVar12;
  int local_68;
  undefined2 local_64;
  undefined2 local_62;
  undefined2 local_60;
  float local_5c;
  float local_58;
  float local_54;
  float local_50;
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
  uVar12 = FUN_802860d8();
  iVar1 = (int)(uVar12 >> 0x20);
  iVar5 = *(int *)(iVar1 + 0xb8);
  iVar2 = FUN_8002b9ec();
  iVar2 = *(int *)(iVar2 + 0xb8);
  *(float *)(iVar5 + 0x20) = FLOAT_803e42c0;
  if ((uVar12 & 0xff) == 0) {
    *(float *)(iVar5 + 0x24) = FLOAT_803e42d4;
    *(float *)(iVar5 + 0x28) = FLOAT_803e42d8;
  }
  else {
    *(float *)(iVar5 + 0x24) = FLOAT_803e42c8 * *(float *)(iVar2 + 0x298) + FLOAT_803e42c4;
    *(float *)(iVar5 + 0x28) = FLOAT_803e42d0 * *(float *)(iVar2 + 0x298) + FLOAT_803e42cc;
  }
  local_58 = FLOAT_803e42c0;
  local_54 = FLOAT_803e42c0;
  local_50 = FLOAT_803e42c0;
  local_5c = FLOAT_803e42dc;
  local_60 = 0;
  local_62 = 0;
  local_64 = *(undefined2 *)(iVar5 + 0x50);
  FUN_80021ac8(&local_64,iVar5 + 0x20);
  *(byte *)(iVar5 + 0x49) = *(byte *)(iVar5 + 0x49) | 1;
  FUN_8000bb18(iVar1,0xd3);
  *(byte *)(iVar5 + 0x49) = *(byte *)(iVar5 + 0x49) | 2;
  if ((*(byte *)(iVar5 + 0x48) >> 6 & 1) != 0) {
    iVar5 = *(int *)(iVar1 + 0x4c);
    iVar2 = 0;
    if (*(short *)(iVar5 + 0x1a) == 0) {
      iVar2 = FUN_80036e58(0x3a,iVar1,0);
    }
    else {
      puVar3 = (undefined4 *)FUN_80036f50(0x3a,&local_68);
      puVar6 = puVar3;
      for (iVar7 = 0; iVar7 < local_68; iVar7 = iVar7 + 1) {
        iVar4 = FUN_80221670(*puVar6);
        if (*(short *)(iVar5 + 0x1a) == iVar4) {
          iVar2 = puVar3[iVar7];
          break;
        }
        puVar6 = puVar6 + 1;
      }
    }
    if (iVar2 != 0) {
      dVar11 = (double)*(float *)(iVar1 + 0xc);
      dVar10 = (double)*(float *)(iVar1 + 0x10);
      dVar9 = (double)*(float *)(iVar1 + 0x14);
      *(undefined4 *)(iVar1 + 0xc) = *(undefined4 *)(iVar2 + 0xc);
      *(undefined4 *)(iVar1 + 0x10) = *(undefined4 *)(iVar2 + 0x10);
      *(undefined4 *)(iVar1 + 0x14) = *(undefined4 *)(iVar2 + 0x14);
      FUN_800e8370(iVar1);
      *(float *)(iVar1 + 0xc) = (float)dVar11;
      *(float *)(iVar1 + 0x10) = (float)dVar10;
      *(float *)(iVar1 + 0x14) = (float)dVar9;
    }
  }
  __psq_l0(auStack8,uVar8);
  __psq_l1(auStack8,uVar8);
  __psq_l0(auStack24,uVar8);
  __psq_l1(auStack24,uVar8);
  __psq_l0(auStack40,uVar8);
  __psq_l1(auStack40,uVar8);
  FUN_80286124();
  return;
}

