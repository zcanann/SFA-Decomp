// Function: FUN_80232138
// Entry: 80232138
// Size: 320 bytes

void FUN_80232138(int param_1,int param_2)

{
  float fVar1;
  int iVar2;
  int iVar3;
  double dVar4;
  
  iVar3 = *(int *)(param_1 + 0x4c);
  iVar2 = FUN_80222358((double)*(float *)(param_2 + 0x108),(double)FLOAT_803e719c,
                       (double)*(float *)(param_2 + 0x108),param_1,param_2,1);
  if (iVar2 == -1) {
    *(ushort *)(param_1 + 6) = *(ushort *)(param_1 + 6) | 0x4000;
    FUN_80035f00(param_1);
    *(undefined *)(param_2 + 0x159) = 4;
  }
  else {
    if (iVar2 != 0) {
      FUN_80231c90(param_1,param_2);
    }
    if (*(char *)(iVar3 + 0x2f) == '\x02') {
      if (*(char *)(param_2 + 0x15c) == '\x02') {
        FUN_80222550((double)FLOAT_803e71a0,(double)FLOAT_803e7188,param_1,param_1 + 0x24,0xf);
      }
      else {
        fVar1 = FLOAT_803e71a0;
        if ((*(byte *)(param_2 + 0x160) >> 3 & 1) != 0) {
          fVar1 = FLOAT_803e7168;
        }
        FUN_80222550((double)fVar1,(double)FLOAT_803e7188,param_1,param_1 + 0x24,0xf);
      }
    }
    dVar4 = (double)FUN_80021370((double)(*(float *)(param_2 + 0x10c) - *(float *)(param_2 + 0x108))
                                 ,(double)FLOAT_803e71a4,(double)FLOAT_803db414);
    *(float *)(param_2 + 0x108) = (float)((double)*(float *)(param_2 + 0x108) + dVar4);
    FUN_8002b95c((double)(*(float *)(param_1 + 0x24) * FLOAT_803db414),
                 (double)(*(float *)(param_1 + 0x28) * FLOAT_803db414),
                 (double)(*(float *)(param_1 + 0x2c) * FLOAT_803db414),param_1);
  }
  return;
}

