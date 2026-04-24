// Function: FUN_800e17c8
// Entry: 800e17c8
// Size: 856 bytes

/* WARNING: Removing unreachable block (ram,0x800e1af8) */
/* WARNING: Removing unreachable block (ram,0x800e1af0) */
/* WARNING: Removing unreachable block (ram,0x800e1b00) */

int FUN_800e17c8(undefined8 param_1,undefined8 param_2,undefined8 param_3,int param_4,float *param_5
                )

{
  int iVar1;
  int iVar2;
  uint uVar3;
  int iVar4;
  bool bVar5;
  undefined4 uVar6;
  undefined8 in_f29;
  undefined8 in_f30;
  undefined8 in_f31;
  float local_78;
  float local_74;
  float local_70;
  uint local_6c [4];
  undefined auStack92 [32];
  undefined auStack40 [16];
  undefined auStack24 [16];
  undefined auStack8 [8];
  
  uVar6 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  __psq_st0(auStack24,(int)((ulonglong)in_f30 >> 0x20),0);
  __psq_st1(auStack24,(int)in_f30,0);
  __psq_st0(auStack40,(int)((ulonglong)in_f29 >> 0x20),0);
  __psq_st1(auStack40,(int)in_f29,0);
LAB_800e1a18:
  do {
    bVar5 = false;
    if ((*(int *)(param_4 + 0x1c) == -1) || ((*(byte *)(param_4 + 0x1b) & 1) != 0)) {
      if ((*(int *)(param_4 + 0x20) == -1) || ((*(byte *)(param_4 + 0x1b) & 2) != 0)) {
        if ((*(int *)(param_4 + 0x24) == -1) || ((*(byte *)(param_4 + 0x1b) & 4) != 0)) {
          if ((*(int *)(param_4 + 0x28) == -1) || ((*(byte *)(param_4 + 0x1b) & 8) != 0)) {
            bVar5 = true;
          }
          else {
            bVar5 = false;
          }
        }
        else {
          bVar5 = false;
        }
      }
      else {
        bVar5 = false;
      }
    }
    if (bVar5) {
      *param_5 = FLOAT_803e0638;
      goto LAB_800e1af0;
    }
    FUN_800e47c4(param_4,auStack92);
    iVar1 = FUN_800e1b24(param_1,param_2,param_3,auStack92,&local_70,&local_74,&local_78);
    if ((((iVar1 != 0) && (FLOAT_803e0648 < local_70)) && (local_70 < FLOAT_803e064c)) &&
       ((FLOAT_803e0650 < local_74 && (local_74 < FLOAT_803e0654)))) {
      *param_5 = local_78;
LAB_800e1af0:
      __psq_l0(auStack8,uVar6);
      __psq_l1(auStack8,uVar6);
      __psq_l0(auStack24,uVar6);
      __psq_l1(auStack24,uVar6);
      __psq_l0(auStack40,uVar6);
      __psq_l1(auStack40,uVar6);
      return param_4;
    }
    iVar1 = 0;
    uVar3 = *(uint *)(param_4 + 0x1c);
    if (((-1 < (int)uVar3) && ((*(byte *)(param_4 + 0x1b) & 1) == 0)) && (uVar3 != 0)) {
      iVar1 = 1;
      local_6c[0] = uVar3;
    }
    uVar3 = *(uint *)(param_4 + 0x20);
    iVar2 = iVar1;
    if (((-1 < (int)uVar3) && ((*(byte *)(param_4 + 0x1b) & 2) == 0)) && (uVar3 != 0)) {
      iVar2 = iVar1 + 1;
      local_6c[iVar1] = uVar3;
    }
    uVar3 = *(uint *)(param_4 + 0x24);
    iVar1 = iVar2;
    if (((-1 < (int)uVar3) && ((*(byte *)(param_4 + 0x1b) & 4) == 0)) && (uVar3 != 0)) {
      iVar1 = iVar2 + 1;
      local_6c[iVar2] = uVar3;
    }
    uVar3 = *(uint *)(param_4 + 0x28);
    iVar2 = iVar1;
    if (((-1 < (int)uVar3) && ((*(byte *)(param_4 + 0x1b) & 8) == 0)) && (uVar3 != 0)) {
      iVar2 = iVar1 + 1;
      local_6c[iVar1] = uVar3;
    }
    if (iVar2 == 0) {
      uVar3 = 0xffffffff;
    }
    else {
      iVar1 = FUN_800221a0(0,iVar2 + -1);
      uVar3 = local_6c[iVar1];
    }
    if ((int)uVar3 < 0) {
      param_4 = 0;
    }
    else {
      iVar2 = DAT_803dd478 + -1;
      iVar1 = 0;
      while (iVar1 <= iVar2) {
        iVar4 = iVar2 + iVar1 >> 1;
        param_4 = (&DAT_803a17e8)[iVar4];
        if (*(uint *)(param_4 + 0x14) < uVar3) {
          iVar1 = iVar4 + 1;
        }
        else {
          if (*(uint *)(param_4 + 0x14) <= uVar3) goto LAB_800e1a18;
          iVar2 = iVar4 + -1;
        }
      }
      param_4 = 0;
    }
  } while( true );
}

