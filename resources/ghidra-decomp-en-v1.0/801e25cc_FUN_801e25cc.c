// Function: FUN_801e25cc
// Entry: 801e25cc
// Size: 1212 bytes

/* WARNING: Removing unreachable block (ram,0x801e2a68) */

void FUN_801e25cc(void)

{
  int iVar1;
  int iVar2;
  int iVar3;
  int iVar4;
  float *pfVar5;
  undefined4 uVar6;
  undefined8 in_f31;
  double dVar7;
  int local_68;
  undefined auStack100 [6];
  undefined2 local_5e;
  float local_5c;
  float local_58;
  float local_54;
  float local_50 [2];
  undefined4 local_48;
  uint uStack68;
  undefined4 local_40;
  uint uStack60;
  longlong local_38;
  undefined auStack8 [8];
  
  uVar6 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  iVar1 = FUN_802860d8();
  pfVar5 = *(float **)(iVar1 + 0xb8);
  iVar2 = (**(code **)(**(int **)(*(int *)(iVar1 + 0x30) + 0x68) + 0x24))();
  iVar3 = (**(code **)(**(int **)(*(int *)(iVar1 + 0x30) + 0x68) + 0x28))();
  if (((*(char *)(pfVar5 + 3) != '\0') && (iVar3 < 6)) && (*(short *)(iVar1 + 0x46) != 0x69c)) {
    FUN_8000da58(iVar1,0x2c6);
  }
  iVar4 = FUN_801e12dc(*(undefined4 *)(iVar1 + 0x30));
  if ((iVar4 < 2) && (*(char *)(pfVar5 + 3) < '\x01')) {
    *pfVar5 = *pfVar5 - FLOAT_803db414;
    if (*pfVar5 <= FLOAT_803e5814) {
      iVar4 = FUN_800221a0(10,0x19);
      dVar7 = (double)FLOAT_803e5810;
      for (; iVar4 != 0; iVar4 = iVar4 + -1) {
        local_58 = *(float *)(iVar1 + 0x18);
        local_54 = *(float *)(iVar1 + 0x1c);
        local_50[0] = *(float *)(iVar1 + 0x20);
        local_5c = (float)dVar7;
        (**(code **)(*DAT_803dca88 + 8))(iVar1,0x9f,auStack100,0x200001,0xffffffff,0);
      }
      uStack68 = FUN_800221a0(0x5a,0xf0);
      uStack68 = uStack68 ^ 0x80000000;
      local_48 = 0x43300000;
      *pfVar5 = (float)((double)CONCAT44(0x43300000,uStack68) - DOUBLE_803e5828);
    }
    if ((2 < iVar2) && (*(char *)(iVar1 + 0xad) == '\x01')) {
      local_5c = FLOAT_803e5818;
      local_5e = 0xc0a;
      FUN_8003842c(iVar1,0,&local_58,&local_54,local_50,0);
      local_58 = local_58 - *(float *)(iVar1 + 0x18);
      local_54 = local_54 - *(float *)(iVar1 + 0x1c);
      local_50[0] = local_50[0] - *(float *)(iVar1 + 0x20);
      for (iVar4 = 0; iVar4 < (int)(uint)DAT_803db410; iVar4 = iVar4 + 1) {
        (**(code **)(*DAT_803dca88 + 8))(iVar1,0x7aa,auStack100,2,0xffffffff,0);
      }
    }
  }
  if (*(int *)(iVar1 + 0x30) != 0) {
    if ((*(short *)(iVar1 + 0x46) != 0x69c) && (*(int *)(*(int *)(iVar1 + 0x30) + 0xf4) < 4)) {
      uStack68 = (uint)pfVar5[2] ^ 0x80000000;
      local_48 = 0x43300000;
      pfVar5[1] = (float)((double)CONCAT44(0x43300000,uStack68) - DOUBLE_803e5828) / FLOAT_803e581c;
      if (pfVar5[1] < FLOAT_803e5814) {
        pfVar5[1] = -pfVar5[1];
      }
      if (pfVar5[1] < FLOAT_803e5820) {
        pfVar5[1] = FLOAT_803e5820;
      }
    }
    *(uint *)(iVar1 + 0xf4) = *(int *)(iVar1 + 0xf4) - (uint)DAT_803db410;
    if (*(int *)(iVar1 + 0xf4) < 0) {
      *(undefined4 *)(iVar1 + 0xf4) = 0;
    }
    if (((((((iVar3 == 1) && (iVar3 = FUN_8003687c(iVar1,&local_68,0,0), iVar3 != 0)) &&
           (*(int *)(iVar1 + 0xf4) == 0)) &&
          ((local_68 != 0 && (iVar3 = FUN_8002b9ec(), local_68 != iVar3)))) &&
         ((*(short *)(local_68 + 0x46) != 0x69c &&
          ((*(short *)(local_68 + 0x46) != 0x9a &&
           (*(undefined4 *)(iVar1 + 0xf4) = 0x14, *(int *)(iVar1 + 0x30) != 0)))))) &&
        ((iVar2 == 2 || (iVar2 == 5)))) && (*(short *)(iVar1 + 0x46) == 0x69c)) {
      FUN_8002ac30(iVar1,0xf,200,0,0,1);
      FUN_8000bb18(iVar1,0x2c7);
      *(char *)(pfVar5 + 3) = *(char *)(pfVar5 + 3) + -1;
      if (*(char *)(pfVar5 + 3) < '\x01') {
        *(undefined *)(pfVar5 + 3) = 0;
        (**(code **)(**(int **)(*(int *)(iVar1 + 0x30) + 0x68) + 0x20))();
        FUN_80035f00(iVar1);
        *(ushort *)(iVar1 + 6) = *(ushort *)(iVar1 + 6) | 0x4000;
        FUN_8009ab70((double)FLOAT_803e5824,iVar1,1,1,1,0,1,1,0);
        FUN_8000bb18(iVar1,0x2c8);
      }
    }
    if (*(int *)(iVar1 + 0xf4) == 0) {
      *(undefined *)(*(int *)(iVar1 + 0x54) + 0x6e) = 6;
      *(undefined *)(*(int *)(iVar1 + 0x54) + 0x6f) = 1;
      *(undefined4 *)(*(int *)(iVar1 + 0x54) + 0x48) = 0x10;
      *(undefined4 *)(*(int *)(iVar1 + 0x54) + 0x4c) = 0x10;
    }
    else {
      *(undefined *)(*(int *)(iVar1 + 0x54) + 0x6c) = 0;
    }
    uStack68 = (uint)pfVar5[2] ^ 0x80000000;
    local_48 = 0x43300000;
    uStack60 = (int)*(short *)(iVar1 + 4) ^ 0x80000000;
    local_40 = 0x43300000;
    iVar2 = (int)-((float)((double)CONCAT44(0x43300000,uStack68) - DOUBLE_803e5828) * FLOAT_803db414
                  - (float)((double)CONCAT44(0x43300000,uStack60) - DOUBLE_803e5828));
    local_38 = (longlong)iVar2;
    *(short *)(iVar1 + 4) = (short)iVar2;
  }
  __psq_l0(auStack8,uVar6);
  __psq_l1(auStack8,uVar6);
  FUN_80286124();
  return;
}

