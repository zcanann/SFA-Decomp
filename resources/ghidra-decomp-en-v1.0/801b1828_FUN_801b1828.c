// Function: FUN_801b1828
// Entry: 801b1828
// Size: 656 bytes

/* WARNING: Removing unreachable block (ram,0x801b1a90) */
/* WARNING: Removing unreachable block (ram,0x801b1a98) */

void FUN_801b1828(void)

{
  int iVar1;
  int iVar2;
  int iVar3;
  char *pcVar4;
  undefined4 uVar5;
  undefined8 in_f30;
  double dVar6;
  double dVar7;
  undefined8 in_f31;
  undefined auStack104 [8];
  float local_60;
  float local_5c;
  float local_58;
  float local_54;
  undefined4 local_50;
  uint uStack76;
  undefined4 local_48;
  uint uStack68;
  undefined auStack24 [16];
  undefined auStack8 [8];
  
  uVar5 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  __psq_st0(auStack24,(int)((ulonglong)in_f30 >> 0x20),0);
  __psq_st1(auStack24,(int)in_f30,0);
  iVar1 = FUN_802860dc();
  pcVar4 = *(char **)(iVar1 + 0xb8);
  iVar3 = *(int *)(iVar1 + 0x4c);
  *(byte *)(iVar1 + 0xaf) = *(byte *)(iVar1 + 0xaf) | 8;
  if (pcVar4[1] == '\0') {
    if (*pcVar4 < '\x01') {
      uStack76 = (int)*(char *)(iVar3 + 0x19) ^ 0x80000000;
      local_50 = 0x43300000;
      local_60 = (float)((double)CONCAT44(0x43300000,uStack76) - DOUBLE_803e4890) / FLOAT_803e4880;
      local_54 = FLOAT_803e4884;
      iVar2 = 0x2d;
      dVar6 = (double)FLOAT_803e4888;
      dVar7 = DOUBLE_803e4890;
      do {
        uStack76 = FUN_800221a0(0xffffff06,0xfa);
        uStack76 = uStack76 ^ 0x80000000;
        local_50 = 0x43300000;
        local_5c = local_60 *
                   (float)(dVar6 * (double)(float)((double)CONCAT44(0x43300000,uStack76) - dVar7));
        uStack68 = FUN_800221a0(0,0x1c2);
        uStack68 = uStack68 ^ 0x80000000;
        local_48 = 0x43300000;
        local_58 = local_60 *
                   (float)(dVar6 * (double)(float)((double)CONCAT44(0x43300000,uStack68) - dVar7));
        (**(code **)(*DAT_803dca88 + 8))(iVar1,0x7f9,auStack104,2,0xffffffff,0);
        iVar2 = iVar2 + -1;
      } while (iVar2 != 0);
      iVar2 = 0x19;
      dVar6 = (double)FLOAT_803e4888;
      dVar7 = DOUBLE_803e4890;
      do {
        uStack68 = FUN_800221a0(0xffffff06,0xfa);
        uStack68 = uStack68 ^ 0x80000000;
        local_48 = 0x43300000;
        local_5c = local_60 *
                   (float)(dVar6 * (double)(float)((double)CONCAT44(0x43300000,uStack68) - dVar7));
        uStack76 = FUN_800221a0(0,0x1c2);
        uStack76 = uStack76 ^ 0x80000000;
        local_50 = 0x43300000;
        local_58 = local_60 *
                   (float)(dVar6 * (double)(float)((double)CONCAT44(0x43300000,uStack76) - dVar7));
        (**(code **)(*DAT_803dca88 + 8))(iVar1,0x7fa,auStack104,2,0xffffffff,0);
        iVar2 = iVar2 + -1;
      } while (iVar2 != 0);
      if (*(int *)(iVar3 + 0x14) != 0x1d09) {
        FUN_8000bb18(iVar1,0x47b);
      }
      pcVar4[1] = '\x01';
      if (*(short *)(iVar3 + 0x1e) != -1) {
        FUN_800200e8((int)*(short *)(iVar3 + 0x1e),1);
      }
    }
    else {
      iVar3 = FUN_8002b9ac();
      if (iVar3 != 0) {
        if ((*(byte *)(iVar1 + 0xaf) & 4) != 0) {
          (**(code **)(**(int **)(iVar3 + 0x68) + 0x28))(iVar3,iVar1,1,4);
        }
        *(byte *)(iVar1 + 0xaf) = *(byte *)(iVar1 + 0xaf) & 0xf7;
        FUN_80041018(iVar1);
      }
    }
  }
  __psq_l0(auStack8,uVar5);
  __psq_l1(auStack8,uVar5);
  __psq_l0(auStack24,uVar5);
  __psq_l1(auStack24,uVar5);
  FUN_80286128();
  return;
}

