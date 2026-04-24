// Function: FUN_802be6e8
// Entry: 802be6e8
// Size: 560 bytes

void FUN_802be6e8(undefined2 *param_1)

{
  float fVar1;
  undefined2 *puVar2;
  char cVar4;
  uint uVar3;
  uint *puVar5;
  
  puVar5 = *(uint **)(param_1 + 0x5c);
  FUN_8002b9ec();
  puVar2 = (undefined2 *)FUN_8000faac();
  *(undefined *)(puVar5 + 0xd5) = 0;
  *puVar5 = *puVar5 & 0xffff7fff;
  fVar1 = FLOAT_803e8304;
  if (*(char *)((int)puVar5 + 0x14e6) == '\x02') {
    cVar4 = FUN_80014cc0(0);
    puVar5[0xa4] = (uint)(float)((double)CONCAT44(0x43300000,(int)cVar4 ^ 0x80000000) -
                                DOUBLE_803e82e0);
    cVar4 = FUN_80014c6c(0);
    puVar5[0xa3] = (uint)(float)((double)CONCAT44(0x43300000,(int)cVar4 ^ 0x80000000) -
                                DOUBLE_803e82e0);
    uVar3 = FUN_80014e70(0);
    puVar5[199] = uVar3;
    uVar3 = FUN_80014ee8(0);
    puVar5[0xc6] = uVar3;
    *(undefined2 *)(puVar5 + 0xcc) = *puVar2;
  }
  else {
    puVar5[0xa4] = (uint)FLOAT_803e8304;
    puVar5[0xa3] = (uint)fVar1;
    puVar5[199] = 0;
    puVar5[0xc6] = 0;
    *(undefined2 *)(puVar5 + 0xcc) = 0;
  }
  *puVar5 = *puVar5 | 0x1000000;
  FUN_802b0ea4(param_1,puVar5 + 0x2d6,puVar5);
  (**(code **)(*DAT_803dca8c + 8))
            ((double)FLOAT_803db414,(double)FLOAT_803db414,param_1,puVar5,&DAT_803db1b0,
             &DAT_803de4d4);
  param_1[1] = param_1[1] + (*(short *)(puVar5 + 0x67) >> 2);
  param_1[2] = param_1[2] + (*(short *)((int)puVar5 + 0x19e) >> 2);
  if ((*(byte *)(puVar5 + 0x53b) >> 1 & 1) != 0) {
    (**(code **)(*DAT_803dca68 + 0x5c))((int)*(short *)((int)puVar5 + 0x14e2));
  }
  FUN_802b1bf8((double)FLOAT_803db414,param_1,puVar5 + 0x2d6,puVar5);
  FUN_802b1b28((double)FLOAT_803db414,param_1);
  (**(code **)(*DAT_803dcaa8 + 0x10))((double)FLOAT_803db414,param_1,puVar5 + 1);
  (**(code **)(*DAT_803dcaa8 + 0x14))(param_1,puVar5 + 1);
  (**(code **)(*DAT_803dcaa8 + 0x18))((double)FLOAT_803db414,param_1,puVar5 + 1);
  *param_1 = *(undefined2 *)(puVar5 + 0x3f4);
  return;
}

