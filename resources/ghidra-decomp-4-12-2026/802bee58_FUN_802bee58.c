// Function: FUN_802bee58
// Entry: 802bee58
// Size: 560 bytes

void FUN_802bee58(short *param_1)

{
  float fVar1;
  undefined2 *puVar2;
  char cVar4;
  uint uVar3;
  uint *puVar5;
  
  puVar5 = *(uint **)(param_1 + 0x5c);
  FUN_8002bac4();
  puVar2 = FUN_8000facc();
  *(undefined *)(puVar5 + 0xd5) = 0;
  *puVar5 = *puVar5 & 0xffff7fff;
  fVar1 = FLOAT_803e8f9c;
  if (*(char *)((int)puVar5 + 0x14e6) == '\x02') {
    cVar4 = FUN_80014cec(0);
    puVar5[0xa4] = (uint)(float)((double)CONCAT44(0x43300000,(int)cVar4 ^ 0x80000000) -
                                DOUBLE_803e8f78);
    cVar4 = FUN_80014c98(0);
    puVar5[0xa3] = (uint)(float)((double)CONCAT44(0x43300000,(int)cVar4 ^ 0x80000000) -
                                DOUBLE_803e8f78);
    uVar3 = FUN_80014e9c(0);
    puVar5[199] = uVar3;
    uVar3 = FUN_80014f14(0);
    puVar5[0xc6] = uVar3;
    *(undefined2 *)(puVar5 + 0xcc) = *puVar2;
  }
  else {
    puVar5[0xa4] = (uint)FLOAT_803e8f9c;
    puVar5[0xa3] = (uint)fVar1;
    puVar5[199] = 0;
    puVar5[0xc6] = 0;
    *(undefined2 *)(puVar5 + 0xcc) = 0;
  }
  *puVar5 = *puVar5 | 0x1000000;
  FUN_802b1604(param_1,(int)(puVar5 + 0x2d6),(int)puVar5);
  (**(code **)(*DAT_803dd70c + 8))
            ((double)FLOAT_803dc074,(double)FLOAT_803dc074,param_1,puVar5,&DAT_803dbe10,
             &DAT_803df154);
  param_1[1] = param_1[1] + (*(short *)(puVar5 + 0x67) >> 2);
  param_1[2] = param_1[2] + (*(short *)((int)puVar5 + 0x19e) >> 2);
  if ((*(byte *)(puVar5 + 0x53b) >> 1 & 1) != 0) {
    (**(code **)(*DAT_803dd6e8 + 0x5c))((int)*(short *)((int)puVar5 + 0x14e2));
  }
  FUN_802b2358((int)param_1,(int)(puVar5 + 0x2d6),puVar5);
  FUN_802b2288((double)FLOAT_803dc074,(int)param_1);
  (**(code **)(*DAT_803dd728 + 0x10))((double)FLOAT_803dc074,param_1,puVar5 + 1);
  (**(code **)(*DAT_803dd728 + 0x14))(param_1,puVar5 + 1);
  (**(code **)(*DAT_803dd728 + 0x18))((double)FLOAT_803dc074,param_1,puVar5 + 1);
  *param_1 = *(short *)(puVar5 + 0x3f4);
  return;
}

