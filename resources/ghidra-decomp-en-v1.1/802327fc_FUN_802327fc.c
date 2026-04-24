// Function: FUN_802327fc
// Entry: 802327fc
// Size: 320 bytes

void FUN_802327fc(ushort *param_1,float *param_2)

{
  float fVar1;
  int iVar2;
  int iVar3;
  double dVar4;
  
  iVar3 = *(int *)(param_1 + 0x26);
  iVar2 = FUN_802229a8((double)param_2[0x42],(double)FLOAT_803e7e34,(double)param_2[0x42],
                       (int)param_1,param_2,'\x01');
  if (iVar2 == -1) {
    param_1[3] = param_1[3] | 0x4000;
    FUN_80035ff8((int)param_1);
    *(undefined *)((int)param_2 + 0x159) = 4;
  }
  else {
    if (iVar2 != 0) {
      FUN_80232354();
    }
    if (*(char *)(iVar3 + 0x2f) == '\x02') {
      if (*(char *)(param_2 + 0x57) == '\x02') {
        FUN_80222ba0((double)FLOAT_803e7e38,(double)FLOAT_803e7e20,param_1,(float *)(param_1 + 0x12)
                     ,0xf);
      }
      else {
        fVar1 = FLOAT_803e7e38;
        if ((*(byte *)(param_2 + 0x58) >> 3 & 1) != 0) {
          fVar1 = FLOAT_803e7e00;
        }
        FUN_80222ba0((double)fVar1,(double)FLOAT_803e7e20,param_1,(float *)(param_1 + 0x12),0xf);
      }
    }
    dVar4 = FUN_80021434((double)(param_2[0x43] - param_2[0x42]),(double)FLOAT_803e7e3c,
                         (double)FLOAT_803dc074);
    param_2[0x42] = (float)((double)param_2[0x42] + dVar4);
    FUN_8002ba34((double)(*(float *)(param_1 + 0x12) * FLOAT_803dc074),
                 (double)(*(float *)(param_1 + 0x14) * FLOAT_803dc074),
                 (double)(*(float *)(param_1 + 0x16) * FLOAT_803dc074),(int)param_1);
  }
  return;
}

