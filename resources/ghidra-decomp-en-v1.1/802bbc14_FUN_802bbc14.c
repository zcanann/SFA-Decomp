// Function: FUN_802bbc14
// Entry: 802bbc14
// Size: 620 bytes

void FUN_802bbc14(undefined4 param_1,undefined4 param_2,int param_3)

{
  float fVar1;
  float fVar2;
  uint uVar3;
  int iVar4;
  undefined2 *puVar5;
  uint uVar6;
  char cVar7;
  uint *puVar8;
  undefined8 uVar9;
  
  uVar9 = FUN_80286840();
  iVar4 = (int)((ulonglong)uVar9 >> 0x20);
  if (param_3 == -1) {
    uVar3 = 1;
  }
  else {
    uVar3 = countLeadingZeros((DAT_803dc070 - 1) - param_3);
    uVar3 = uVar3 >> 5;
  }
  puVar5 = FUN_8000facc();
  puVar8 = *(uint **)(iVar4 + 0xb8);
  *(undefined *)(puVar8 + 0xd5) = 0;
  *puVar8 = *puVar8 & 0xffff7fff;
  fVar1 = FLOAT_803e8ecc;
  if (*(char *)((int)puVar8 + 0xa8a) == '\x02') {
    uVar6 = FUN_80020078(0x3e2);
    if (uVar6 == 0) {
      *(undefined2 *)(puVar8 + 0x2a2) = 1000;
    }
    else {
      *(short *)(puVar8 + 0x2a2) = *(short *)(puVar8 + 0x2a2) + -1;
    }
    (**(code **)(*DAT_803dd6e8 + 0x5c))((int)*(short *)(puVar8 + 0x2a2));
    uVar6 = FUN_80020078(0x3e9);
    if (uVar6 != 0) {
      FUN_800201ac(0x3e9,0);
      *(undefined2 *)(puVar8 + 0x2a2) = 1000;
    }
    if (*(short *)(puVar8 + 0x2a2) < 0) {
      *(undefined2 *)(puVar8 + 0x2a2) = 0;
      (**(code **)(*DAT_803dd72c + 0x28))();
    }
    cVar7 = FUN_80014cec(0);
    puVar8[0xa4] = (uint)(float)((double)CONCAT44(0x43300000,(int)cVar7 ^ 0x80000000) -
                                DOUBLE_803e8f08);
    cVar7 = FUN_80014c98(0);
    puVar8[0xa3] = (uint)(float)((double)CONCAT44(0x43300000,(int)cVar7 ^ 0x80000000) -
                                DOUBLE_803e8f08);
    uVar6 = FUN_80014e9c(0);
    puVar8[199] = uVar6;
    uVar6 = FUN_80014f14(0);
    puVar8[0xc6] = uVar6;
    *(undefined2 *)(puVar8 + 0xcc) = *puVar5;
  }
  else {
    puVar8[0xa4] = (uint)FLOAT_803e8ecc;
    puVar8[0xa3] = (uint)fVar1;
    puVar8[199] = 0;
    puVar8[0xc6] = 0;
    *(undefined2 *)(puVar8 + 0xcc) = 0;
  }
  *puVar8 = *puVar8 | 0x400000;
  if (uVar3 != 0) {
    *puVar8 = *puVar8 & 0xffbfffff;
  }
  if (*(char *)((int)puVar8 + 0x25f) != '\0') {
    *(float *)(iVar4 + 0x28) =
         -(FLOAT_803e8f3c *
           (float)((double)CONCAT44(0x43300000,(uint)uVar9 ^ 0x80000000) - DOUBLE_803e8f08) -
          *(float *)(iVar4 + 0x28));
  }
  fVar1 = *(float *)(iVar4 + 0x28);
  fVar2 = FLOAT_803e8f40;
  if ((FLOAT_803e8f40 <= fVar1) && (fVar2 = fVar1, FLOAT_803e8ecc < fVar1)) {
    fVar2 = FLOAT_803e8ecc;
  }
  *(float *)(iVar4 + 0x28) = fVar2;
  (**(code **)(*DAT_803dd70c + 8))
            ((double)FLOAT_803dc074,(double)FLOAT_803dc074,iVar4,puVar8,&DAT_803dbd90,&DAT_803df144)
  ;
  FUN_802bb998(iVar4,puVar8,(int)puVar8);
  FUN_8028688c();
  return;
}

