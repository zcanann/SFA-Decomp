// Function: FUN_80222844
// Entry: 80222844
// Size: 388 bytes

/* WARNING: Removing unreachable block (ram,0x802229a8) */

void FUN_80222844(undefined4 param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4,
                 undefined4 param_5)

{
  bool bVar1;
  int iVar2;
  int iVar3;
  int *piVar4;
  undefined4 uVar5;
  undefined8 in_f31;
  double dVar6;
  undefined8 uVar7;
  undefined2 local_58;
  undefined2 local_56;
  undefined2 local_54;
  float local_50;
  undefined auStack76 [4];
  undefined auStack72 [4];
  undefined auStack68 [60];
  undefined auStack8 [8];
  
  uVar5 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  uVar7 = FUN_802860c8();
  iVar2 = (int)((ulonglong)uVar7 >> 0x20);
  piVar4 = *(int **)(iVar2 + 0xb8);
  FUN_8003b8f4((double)FLOAT_803e6ca0);
  FUN_8003842c(iVar2,0,piVar4 + 5,piVar4 + 6,piVar4 + 7,0);
  local_58 = 0;
  local_54 = 0;
  local_56 = 0x4000;
  iVar3 = 0;
  dVar6 = (double)FLOAT_803e6ca4;
  do {
    FUN_8003842c(iVar2,iVar3 + 1,auStack76,auStack72,auStack68,0);
    FUN_80247754(auStack76,iVar2 + 0xc,auStack76);
    local_50 = (float)dVar6;
    FUN_8009837c((double)FLOAT_803e6ca8,(double)FLOAT_803e6cac,iVar2,3,0,0,&local_58);
    iVar3 = iVar3 + 1;
  } while (iVar3 < 4);
  iVar3 = piVar4[2];
  if (iVar3 != 0) {
    iVar2 = FUN_80036e58(0x19,iVar2,0);
    bVar1 = false;
    if ((iVar2 != 0) && (iVar3 == iVar2)) {
      bVar1 = true;
    }
    if ((bVar1) && (*piVar4 != 4)) {
      *(int *)(piVar4[2] + 0xc) = piVar4[5];
      *(int *)(piVar4[2] + 0x10) = piVar4[6];
      *(int *)(piVar4[2] + 0x14) = piVar4[7];
      FUN_8003b8f4((double)FLOAT_803e6ca0,piVar4[2],(int)uVar7,param_3,param_4,param_5);
    }
  }
  __psq_l0(auStack8,uVar5);
  __psq_l1(auStack8,uVar5);
  FUN_80286114();
  return;
}

