// Function: FUN_801e9518
// Entry: 801e9518
// Size: 588 bytes

void FUN_801e9518(int *param_1)

{
  int iVar1;
  int iVar2;
  float *pfVar3;
  double dVar4;
  float local_80;
  float local_7c [2];
  int local_74;
  int aiStack_70 [7];
  float afStack_54 [18];
  
  pfVar3 = (float *)param_1[0x2e];
  iVar2 = param_1[0x13];
  if (*pfVar3 < (float)param_1[4]) {
    param_1[10] = (int)-(FLOAT_803e670c * FLOAT_803dc074 - (float)param_1[10]);
  }
  FUN_8002ba34((double)(FLOAT_803dc074 * (float)param_1[9] * pfVar3[1]),
               (double)((float)param_1[10] * FLOAT_803dc074),
               (double)(FLOAT_803dc074 * (float)param_1[0xb] * pfVar3[1]),(int)param_1);
  dVar4 = FUN_80293900((double)((float)param_1[9] * (float)param_1[9] +
                               (float)param_1[0xb] * (float)param_1[0xb]));
  FUN_8002f6cc(dVar4,(int)param_1,&local_80);
  FUN_8002fb40((double)local_80,(double)FLOAT_803dc074);
  if ((float)param_1[4] < *pfVar3) {
    param_1[4] = (int)*pfVar3;
    param_1[10] = (int)FLOAT_803e6710;
  }
  iVar1 = FUN_80064248(param_1 + 0x20,param_1 + 3,(float *)0x0,aiStack_70,param_1,8,0xffffffff,0xff,
                       10);
  if (iVar1 != 0) {
    FUN_80022800(afStack_54,(float *)(param_1 + 9),local_7c);
    param_1[9] = (int)local_7c[0];
    param_1[0xb] = local_74;
    iVar1 = FUN_80021884();
    *(short *)param_1 = (short)iVar1;
  }
  iVar1 = FUN_8002bac4();
  dVar4 = FUN_80021730((float *)(iVar1 + 0x18),(float *)(param_1 + 6));
  if (dVar4 < (double)FLOAT_803e6718) {
    FUN_8000bb38((uint)param_1,*(ushort *)(pfVar3 + 3));
    FUN_80099c40((double)FLOAT_803e671c,param_1,(int)*(short *)((int)pfVar3 + 0xe),0x28);
    *(ushort *)(param_1 + 0x2c) = *(ushort *)(param_1 + 0x2c) | 0x8000;
    *(ushort *)((int)param_1 + 6) = *(ushort *)((int)param_1 + 6) | 0x4000;
    (**(code **)(**(int **)((int)pfVar3[2] + 0x68) + 0x50))
              (pfVar3[2],*(char *)(iVar2 + 0x19) != '\0',*(char *)(iVar2 + 0x19) == '\0');
  }
  if (((*(ushort *)(param_1 + 0x2c) & 0x800) != 0) && ((int)*(short *)(pfVar3 + 4) != 0)) {
    FUN_80097568((double)FLOAT_803e671c,(double)FLOAT_803e6720,param_1,5,
                 (int)*(short *)(pfVar3 + 4) & 0xff,1,0x14,0,0);
  }
  return;
}

