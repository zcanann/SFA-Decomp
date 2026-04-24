// Function: FUN_8003be38
// Entry: 8003be38
// Size: 196 bytes

/* WARNING: Removing unreachable block (ram,0x8003bedc) */

void FUN_8003be38(undefined4 param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4)

{
  byte bVar1;
  byte bVar2;
  int iVar3;
  int iVar4;
  int iVar5;
  int iVar6;
  undefined4 uVar7;
  undefined8 in_f31;
  double dVar8;
  undefined auStack8 [8];
  
  uVar7 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  iVar3 = FUN_802860d4();
  iVar4 = FUN_80022a48();
  bVar1 = *(byte *)(iVar3 + 0xf3);
  bVar2 = *(byte *)(iVar3 + 0xf4);
  iVar3 = iVar4 + 0x2700;
  iVar5 = iVar4 + 0x12c0;
  FUN_800229c4(0);
  dVar8 = (double)FLOAT_803dea04;
  for (iVar6 = 0; iVar6 < (int)((uint)bVar1 + (uint)bVar2); iVar6 = iVar6 + 1) {
    FUN_80246eb4(param_3,iVar3,iVar4);
    FUN_80246eb4(iVar4,param_4,iVar5);
    *(float *)(iVar5 + 0xc) = (float)dVar8;
    *(float *)(iVar5 + 0x1c) = (float)dVar8;
    *(float *)(iVar5 + 0x2c) = (float)dVar8;
    iVar3 = iVar3 + 0x40;
    iVar4 = iVar4 + 0x30;
    iVar5 = iVar5 + 0x30;
  }
  DAT_803dcc48 = 2;
  __psq_l0(auStack8,uVar7);
  __psq_l1(auStack8,uVar7);
  FUN_80286120();
  return;
}

