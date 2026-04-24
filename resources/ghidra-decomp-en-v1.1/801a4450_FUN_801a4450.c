// Function: FUN_801a4450
// Entry: 801a4450
// Size: 456 bytes

void FUN_801a4450(undefined4 param_1,undefined4 param_2,int param_3)

{
  byte bVar1;
  int iVar2;
  int iVar3;
  int iVar4;
  uint uVar5;
  byte *pbVar6;
  bool bVar7;
  bool bVar8;
  double dVar9;
  
  iVar2 = FUN_80286840();
  iVar3 = FUN_8002bac4();
  iVar4 = FUN_8002ba84();
  if (iVar3 == 0) {
    bVar7 = false;
  }
  else {
    dVar9 = (double)FUN_80021754((float *)(iVar2 + 0x18),(float *)(iVar3 + 0x18));
    bVar7 = dVar9 < (double)FLOAT_803e5050;
  }
  if (iVar4 == 0) {
    bVar8 = false;
  }
  else {
    dVar9 = (double)FUN_80021754((float *)(iVar2 + 0x18),(float *)(iVar4 + 0x18));
    bVar8 = dVar9 < (double)FLOAT_803e5050;
  }
  pbVar6 = *(byte **)(iVar2 + 0xb8);
  iVar2 = *(int *)(iVar2 + 0x4c);
  if (*pbVar6 >> 5 == 0) {
    uVar5 = FUN_80020078((int)*(short *)(iVar2 + 0x18));
    if (((uVar5 != 0) &&
        (((int)*(short *)(iVar2 + 0x22) == 0xffffffff ||
         (uVar5 = FUN_80020078((int)*(short *)(iVar2 + 0x22)), uVar5 != 0)))) &&
       ((FUN_800201ac((int)*(short *)(iVar2 + 0x1a),1), bVar7 || (bVar8)))) {
      *pbVar6 = *pbVar6 & 0x1f | 0x40;
    }
  }
  else if (((*pbVar6 >> 5 == 1) &&
           (((uVar5 = FUN_80020078((int)*(short *)(iVar2 + 0x18)), uVar5 != 0 ||
             (((int)*(short *)(iVar2 + 0x22) != 0xffffffff &&
              (uVar5 = FUN_80020078((int)*(short *)(iVar2 + 0x22)), uVar5 != 0)))) && (!bVar7)))) &&
          (!bVar8)) {
    *pbVar6 = *pbVar6 & 0x1f | 0x60;
  }
  bVar1 = *pbVar6;
  if (bVar1 >> 5 == 2) {
    if (*(char *)(param_3 + 0x80) == '\x02') {
      *pbVar6 = bVar1 & 0x1f | 0x20;
    }
  }
  else if ((bVar1 >> 5 == 3) && (*(char *)(param_3 + 0x80) == '\x01')) {
    *pbVar6 = bVar1 & 0x1f;
  }
  FUN_8028688c();
  return;
}

