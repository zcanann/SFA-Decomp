// Function: FUN_802c11bc
// Entry: 802c11bc
// Size: 520 bytes

/* WARNING: Removing unreachable block (ram,0x802c139c) */

void FUN_802c11bc(undefined8 param_1,int param_2,int param_3)

{
  float fVar1;
  uint uVar2;
  undefined2 *puVar3;
  char cVar5;
  uint uVar4;
  uint *puVar6;
  undefined4 uVar7;
  undefined8 in_f31;
  undefined auStack8 [8];
  
  uVar7 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  if (param_3 == -1) {
    uVar2 = 1;
  }
  else {
    uVar2 = countLeadingZeros((DAT_803db410 - 1) - param_3);
    uVar2 = uVar2 >> 5;
  }
  puVar3 = (undefined2 *)FUN_8000faac();
  puVar6 = *(uint **)(param_2 + 0xb8);
  *(undefined *)(puVar6 + 0xd5) = 0;
  *puVar6 = *puVar6 & 0xffff7fff;
  *puVar6 = *puVar6 | 0x200000;
  fVar1 = FLOAT_803e83a4;
  if (*(char *)((int)puVar6 + 0xbb2) == '\x02') {
    cVar5 = FUN_80014cc0(0);
    puVar6[0xa4] = (uint)(float)((double)CONCAT44(0x43300000,(int)cVar5 ^ 0x80000000) -
                                DOUBLE_803e8400);
    cVar5 = FUN_80014c6c(0);
    puVar6[0xa3] = (uint)(float)((double)CONCAT44(0x43300000,(int)cVar5 ^ 0x80000000) -
                                DOUBLE_803e8400);
    uVar4 = FUN_80014e70(0);
    puVar6[199] = uVar4;
    uVar4 = FUN_80014ee8(0);
    puVar6[0xc6] = uVar4;
    *(undefined2 *)(puVar6 + 0xcc) = *puVar3;
    if ((*(byte *)(puVar6 + 0x2f0) & 1) != 0) {
      FUN_80222358((double)(float)puVar6[0x2d4],(double)FLOAT_803e83b4,(double)FLOAT_803e8414,
                   param_2,puVar6 + 0xd7,1);
    }
  }
  else {
    puVar6[0xa4] = (uint)FLOAT_803e83a4;
    puVar6[0xa3] = (uint)fVar1;
    puVar6[199] = 0;
    puVar6[0xc6] = 0;
    *(undefined2 *)(puVar6 + 0xcc) = 0;
  }
  *puVar6 = *puVar6 | 0x400000;
  if (uVar2 != 0) {
    *puVar6 = *puVar6 & 0xffbfffff;
  }
  (**(code **)(*DAT_803dca8c + 8))
            (param_1,(double)FLOAT_803db414,param_2,puVar6,&DAT_803db1c0,&DAT_803de4e0);
  if ((puVar6[0xc5] & 1) != 0) {
    FUN_802bf4d8(param_2);
  }
  if ((*(byte *)(puVar6 + 0x2f0) >> 1 & 1) != 0) {
    (**(code **)(*DAT_803dca68 + 0x5c))(*(short *)(puVar6 + 0x2ec) - DAT_803de4d8);
  }
  __psq_l0(auStack8,uVar7);
  __psq_l1(auStack8,uVar7);
  return;
}

