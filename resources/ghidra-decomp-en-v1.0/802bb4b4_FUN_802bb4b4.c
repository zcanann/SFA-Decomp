// Function: FUN_802bb4b4
// Entry: 802bb4b4
// Size: 620 bytes

void FUN_802bb4b4(undefined4 param_1,undefined4 param_2,int param_3)

{
  float fVar1;
  float fVar2;
  uint uVar3;
  int iVar4;
  undefined2 *puVar5;
  int iVar6;
  char cVar8;
  uint uVar7;
  uint *puVar9;
  undefined8 uVar10;
  
  uVar10 = FUN_802860dc();
  iVar4 = (int)((ulonglong)uVar10 >> 0x20);
  if (param_3 == -1) {
    uVar3 = 1;
  }
  else {
    uVar3 = countLeadingZeros((DAT_803db410 - 1) - param_3);
    uVar3 = uVar3 >> 5;
  }
  puVar5 = (undefined2 *)FUN_8000faac();
  puVar9 = *(uint **)(iVar4 + 0xb8);
  *(undefined *)(puVar9 + 0xd5) = 0;
  *puVar9 = *puVar9 & 0xffff7fff;
  fVar1 = FLOAT_803e8234;
  if (*(char *)((int)puVar9 + 0xa8a) == '\x02') {
    iVar6 = FUN_8001ffb4(0x3e2);
    if (iVar6 == 0) {
      *(undefined2 *)(puVar9 + 0x2a2) = 1000;
    }
    else {
      *(short *)(puVar9 + 0x2a2) = *(short *)(puVar9 + 0x2a2) + -1;
    }
    (**(code **)(*DAT_803dca68 + 0x5c))((int)*(short *)(puVar9 + 0x2a2));
    iVar6 = FUN_8001ffb4(0x3e9);
    if (iVar6 != 0) {
      FUN_800200e8(0x3e9,0);
      *(undefined2 *)(puVar9 + 0x2a2) = 1000;
    }
    if (*(short *)(puVar9 + 0x2a2) < 0) {
      *(undefined2 *)(puVar9 + 0x2a2) = 0;
      (**(code **)(*DAT_803dcaac + 0x28))();
    }
    cVar8 = FUN_80014cc0(0);
    puVar9[0xa4] = (uint)(float)((double)CONCAT44(0x43300000,(int)cVar8 ^ 0x80000000) -
                                DOUBLE_803e8270);
    cVar8 = FUN_80014c6c(0);
    puVar9[0xa3] = (uint)(float)((double)CONCAT44(0x43300000,(int)cVar8 ^ 0x80000000) -
                                DOUBLE_803e8270);
    uVar7 = FUN_80014e70(0);
    puVar9[199] = uVar7;
    uVar7 = FUN_80014ee8(0);
    puVar9[0xc6] = uVar7;
    *(undefined2 *)(puVar9 + 0xcc) = *puVar5;
  }
  else {
    puVar9[0xa4] = (uint)FLOAT_803e8234;
    puVar9[0xa3] = (uint)fVar1;
    puVar9[199] = 0;
    puVar9[0xc6] = 0;
    *(undefined2 *)(puVar9 + 0xcc) = 0;
  }
  *puVar9 = *puVar9 | 0x400000;
  if (uVar3 != 0) {
    *puVar9 = *puVar9 & 0xffbfffff;
  }
  if (*(char *)((int)puVar9 + 0x25f) != '\0') {
    *(float *)(iVar4 + 0x28) =
         -(FLOAT_803e82a4 *
           (float)((double)CONCAT44(0x43300000,(uint)uVar10 ^ 0x80000000) - DOUBLE_803e8270) -
          *(float *)(iVar4 + 0x28));
  }
  fVar1 = *(float *)(iVar4 + 0x28);
  fVar2 = FLOAT_803e82a8;
  if ((FLOAT_803e82a8 <= fVar1) && (fVar2 = fVar1, FLOAT_803e8234 < fVar1)) {
    fVar2 = FLOAT_803e8234;
  }
  *(float *)(iVar4 + 0x28) = fVar2;
  (**(code **)(*DAT_803dca8c + 8))
            ((double)FLOAT_803db414,(double)FLOAT_803db414,iVar4,puVar9,&DAT_803db130,&DAT_803de4c4)
  ;
  FUN_802bb238(iVar4,puVar9,puVar9);
  FUN_80286128();
  return;
}

