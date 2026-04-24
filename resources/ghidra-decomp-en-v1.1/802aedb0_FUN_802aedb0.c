// Function: FUN_802aedb0
// Entry: 802aedb0
// Size: 492 bytes

void FUN_802aedb0(uint param_1,int param_2,int param_3,undefined4 param_4,undefined4 param_5,
                 undefined4 param_6,undefined4 param_7,undefined4 param_8)

{
  float fVar1;
  float fVar2;
  int iVar3;
  double dVar4;
  double dVar5;
  double dVar6;
  double dVar7;
  undefined8 in_f4;
  undefined8 in_f5;
  undefined8 in_f6;
  undefined8 in_f7;
  undefined8 in_f8;
  
  iVar3 = *DAT_803dd70c;
  (**(code **)(iVar3 + 0x20))((double)FLOAT_803dc074,param_1,param_3,1);
  dVar6 = (double)*(float *)(param_1 + 0x98);
  dVar7 = (double)FLOAT_803e8b78;
  if (-(double)(float)((double)FLOAT_803e8be8 * (double)*(float *)(param_3 + 0x2a0) - dVar7) <=
      dVar6) {
    *(float *)(param_3 + 0x280) =
         *(float *)(param_2 + 0x844) *
         ((FLOAT_803e8bac + *(float *)(*(int *)(param_2 + 0x400) + 0x14)) -
         *(float *)(param_3 + 0x280)) + *(float *)(param_3 + 0x280);
    *(undefined4 *)(param_3 + 0x294) = *(undefined4 *)(param_3 + 0x280);
    dVar6 = (double)FLOAT_803e8b94;
    *(float *)(param_2 + 0x844) =
         (float)(dVar6 * (double)FLOAT_803dc074 + (double)*(float *)(param_2 + 0x844));
    dVar5 = (double)*(float *)(param_2 + 0x844);
    dVar4 = (double)FLOAT_803e8b3c;
    if ((dVar4 <= dVar5) && (dVar4 = dVar5, dVar7 < dVar5)) {
      dVar4 = dVar7;
    }
    *(float *)(param_2 + 0x844) = (float)dVar4;
  }
  if ((*(uint *)(param_3 + 0x314) & 0x200) != 0) {
    FUN_80014acc((double)FLOAT_803e8ba8);
    FUN_8000bb38(param_1,0x3cd);
    *(ushort *)(param_2 + 0x8d8) = *(ushort *)(param_2 + 0x8d8) | 4;
  }
  fVar1 = FLOAT_803e8c3c;
  *(float *)(param_2 + 0x428) = FLOAT_803e8c3c;
  *(float *)(param_2 + 0x430) = fVar1;
  fVar2 = FLOAT_803e8b6c;
  fVar1 = FLOAT_803e8b3c;
  if ((*(byte *)(param_2 + 0x3f1) >> 4 & 1) == 0) {
    *(float *)(param_2 + 0x42c) = FLOAT_803e8b6c;
    *(float *)(param_2 + 0x434) = fVar2;
  }
  else {
    *(float *)(param_2 + 0x42c) = FLOAT_803e8b3c;
    *(float *)(param_2 + 0x434) = fVar1;
  }
  *(float *)(param_2 + 0x7a4) = FLOAT_803e8d7c;
  if (FLOAT_803e8b78 <= *(float *)(param_1 + 0x98)) {
    *(byte *)(param_2 + 0x3f0) = *(byte *)(param_2 + 0x3f0) & 0xef;
    DAT_803dd2d4 = 1;
    *(byte *)(param_2 + 0x3f1) = *(byte *)(param_2 + 0x3f1) & 0xfd | 2;
    *(byte *)(param_2 + 0x3f1) = *(byte *)(param_2 + 0x3f1) & 0xf7 | 8;
    *(undefined *)(param_2 + 0x8cc) = 0xc;
    *(short *)(param_2 + 0x478) = *(short *)(param_2 + 0x484);
    *(int *)(param_2 + 0x494) = (int)*(short *)(param_2 + 0x484);
    FUN_8003042c((double)FLOAT_803e8b3c,dVar6,dVar7,in_f4,in_f5,in_f6,in_f7,in_f8,param_1,
                 (int)*(short *)(&DAT_80333cb0 + *(char *)(param_2 + 0x8cc) * 2),0,iVar3,param_5,
                 param_6,param_7,param_8);
    FUN_8002f66c(param_1,1);
  }
  return;
}

