// Function: FUN_8017f4f4
// Entry: 8017f4f4
// Size: 708 bytes

/* WARNING: Removing unreachable block (ram,0x8017f790) */

void FUN_8017f4f4(int param_1,undefined4 param_2,int param_3)

{
  short sVar1;
  int iVar2;
  int iVar3;
  undefined2 uVar4;
  undefined4 uVar5;
  double dVar6;
  undefined8 in_f31;
  undefined auStack88 [4];
  undefined auStack84 [4];
  int local_50;
  undefined auStack76 [12];
  float local_40;
  undefined auStack60 [4];
  float local_38 [2];
  undefined4 local_30;
  uint uStack44;
  undefined auStack8 [8];
  
  uVar5 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  iVar2 = FUN_8002b9ec();
  *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) & 0xf7;
  iVar3 = FUN_80036770(param_1,auStack88,auStack84,&local_50,&local_40,auStack60,local_38);
  if ((iVar3 != 0) && (local_50 != 0)) {
    if (iVar3 == 0x10) {
      FUN_8002b050(param_1,300);
    }
    else if ((0xf < iVar3) || (iVar3 != 0)) {
      FUN_8000bb18(param_1,0x5c);
      *(undefined *)(param_3 + 0xf) = 4;
      *(float *)(param_3 + 8) = FLOAT_803e3884;
      FUN_80030334((double)FLOAT_803e385c,param_1,3,0);
      iVar3 = 0x14;
      do {
        (**(code **)(*DAT_803dca88 + 8))(param_1,0x34e,0,2,0xffffffff,0);
        iVar3 = iVar3 + -1;
      } while (iVar3 != 0);
      local_40 = local_40 + FLOAT_803dcdd8;
      local_38[0] = local_38[0] + FLOAT_803dcddc;
      FUN_8009a1dc((double)FLOAT_803e3888,param_1,auStack76,1,0);
      FUN_8002ac30(param_1,0xf,200,0,0,1);
    }
  }
  if (*(char *)(param_3 + 0xf) == '\x01') {
    if (*(short *)(param_1 + 0xa0) == 1) {
      if (*(float *)(param_1 + 0x98) < FLOAT_803e3858) {
        *(float *)(param_3 + 8) = FLOAT_803e3890;
      }
      else {
        *(float *)(param_3 + 8) = FLOAT_803e388c;
        FUN_80030334((double)FLOAT_803e385c,param_1,4,0);
      }
    }
    else {
      sVar1 = *(short *)(param_3 + 0xc) - (ushort)DAT_803db410;
      *(short *)(param_3 + 0xc) = sVar1;
      if (sVar1 < 1) {
        uVar4 = FUN_800221a0(300,600);
        *(undefined2 *)(param_3 + 0xc) = uVar4;
      }
      else if (*(short *)(param_1 + 0xa0) != 4) {
        *(float *)(param_3 + 8) = FLOAT_803e388c;
        uStack44 = FUN_800221a0(0,99);
        uStack44 = uStack44 ^ 0x80000000;
        local_30 = 0x43300000;
        FUN_80030334((double)(FLOAT_803e3890 *
                             (float)((double)CONCAT44(0x43300000,uStack44) - DOUBLE_803e3860)),
                     param_1,4,0);
      }
    }
  }
  dVar6 = (double)FUN_80021704(param_1 + 0x18,iVar2 + 0x18);
  iVar2 = FUN_8000b578(param_1,0x40);
  if (iVar2 == 0) {
    if (dVar6 < (double)FLOAT_803e3894) {
      FUN_8000bb18(param_1,0x5d);
    }
  }
  else if ((double)FLOAT_803e3898 < dVar6) {
    FUN_8000b7bc(param_1,0x40);
  }
  __psq_l0(auStack8,uVar5);
  __psq_l1(auStack8,uVar5);
  return;
}

