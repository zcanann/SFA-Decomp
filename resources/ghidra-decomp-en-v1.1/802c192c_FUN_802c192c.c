// Function: FUN_802c192c
// Entry: 802c192c
// Size: 520 bytes

/* WARNING: Removing unreachable block (ram,0x802c1b0c) */
/* WARNING: Removing unreachable block (ram,0x802c193c) */

void FUN_802c192c(undefined8 param_1,undefined8 param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 ushort *param_9,int param_10)

{
  float fVar1;
  uint uVar2;
  undefined2 *puVar3;
  char cVar5;
  uint uVar4;
  uint *puVar6;
  undefined8 uVar7;
  double dVar8;
  
  if (param_10 == -1) {
    uVar2 = 1;
  }
  else {
    uVar2 = countLeadingZeros((DAT_803dc070 - 1) - param_10);
    uVar2 = uVar2 >> 5;
  }
  puVar3 = FUN_8000facc();
  puVar6 = *(uint **)(param_9 + 0x5c);
  *(undefined *)(puVar6 + 0xd5) = 0;
  *puVar6 = *puVar6 & 0xffff7fff;
  *puVar6 = *puVar6 | 0x200000;
  fVar1 = FLOAT_803e903c;
  if (*(char *)((int)puVar6 + 0xbb2) == '\x02') {
    cVar5 = FUN_80014cec(0);
    puVar6[0xa4] = (uint)(float)((double)CONCAT44(0x43300000,(int)cVar5 ^ 0x80000000) -
                                DOUBLE_803e9098);
    cVar5 = FUN_80014c98(0);
    puVar6[0xa3] = (uint)(float)((double)CONCAT44(0x43300000,(int)cVar5 ^ 0x80000000) -
                                DOUBLE_803e9098);
    uVar4 = FUN_80014e9c(0);
    puVar6[199] = uVar4;
    uVar4 = FUN_80014f14(0);
    puVar6[0xc6] = uVar4;
    *(undefined2 *)(puVar6 + 0xcc) = *puVar3;
    if ((*(byte *)(puVar6 + 0x2f0) & 1) != 0) {
      param_3 = (double)FLOAT_803e90ac;
      FUN_802229a8((double)(float)puVar6[0x2d4],(double)FLOAT_803e904c,param_3,(int)param_9,
                   (float *)(puVar6 + 0xd7),'\x01');
    }
  }
  else {
    puVar6[0xa4] = (uint)FLOAT_803e903c;
    puVar6[0xa3] = (uint)fVar1;
    puVar6[199] = 0;
    puVar6[0xc6] = 0;
    *(undefined2 *)(puVar6 + 0xcc) = 0;
  }
  *puVar6 = *puVar6 | 0x400000;
  if (uVar2 != 0) {
    *puVar6 = *puVar6 & 0xffbfffff;
  }
  dVar8 = (double)FLOAT_803dc074;
  uVar7 = (**(code **)(*DAT_803dd70c + 8))(param_1,param_9,puVar6,&DAT_803dbe20,&DAT_803df160);
  if ((puVar6[0xc5] & 1) != 0) {
    FUN_802bfc48(uVar7,dVar8,param_3,param_4,param_5,param_6,param_7,param_8,param_9);
  }
  if ((*(byte *)(puVar6 + 0x2f0) >> 1 & 1) != 0) {
    (**(code **)(*DAT_803dd6e8 + 0x5c))(*(short *)(puVar6 + 0x2ec) - DAT_803df158);
  }
  return;
}

