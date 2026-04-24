// Function: FUN_80166efc
// Entry: 80166efc
// Size: 556 bytes

/* WARNING: Removing unreachable block (ram,0x80167108) */
/* WARNING: Removing unreachable block (ram,0x80167100) */
/* WARNING: Removing unreachable block (ram,0x801670f8) */
/* WARNING: Removing unreachable block (ram,0x801670f0) */
/* WARNING: Removing unreachable block (ram,0x801670e8) */
/* WARNING: Removing unreachable block (ram,0x80166fe4) */
/* WARNING: Removing unreachable block (ram,0x80166f2c) */
/* WARNING: Removing unreachable block (ram,0x80166f24) */
/* WARNING: Removing unreachable block (ram,0x80166f1c) */
/* WARNING: Removing unreachable block (ram,0x80166f14) */
/* WARNING: Removing unreachable block (ram,0x80166f0c) */

void FUN_80166efc(double param_1,double param_2,double param_3,double param_4,int param_5)

{
  byte bVar1;
  int iVar2;
  double dVar3;
  double dVar4;
  double dVar5;
  double dVar6;
  
  iVar2 = *(int *)(*(int *)(param_5 + 0xb8) + 0x40c);
  if ((*(byte *)(iVar2 + 0x92) >> 2 & 1) == 0) {
    dVar6 = (double)(float)(param_1 - (double)*(float *)(param_5 + 0xc));
    dVar5 = (double)(float)(param_2 - (double)*(float *)(param_5 + 0x10));
    dVar4 = (double)(float)(param_3 - (double)*(float *)(param_5 + 0x14));
    dVar3 = FUN_80293900((double)(float)(dVar4 * dVar4 +
                                        (double)(float)(dVar6 * dVar6 +
                                                       (double)(float)(dVar5 * dVar5))));
    if ((double)FLOAT_803e3c74 <= dVar3) {
      dVar3 = (double)(float)((double)*(float *)(iVar2 + 0x60) / dVar3);
      dVar6 = (double)(float)(dVar6 * dVar3);
      dVar5 = (double)(float)(dVar5 * dVar3);
      dVar4 = (double)(float)(dVar4 * dVar3);
    }
    dVar6 = (double)(float)(param_4 * (double)(float)(dVar6 - (double)*(float *)(param_5 + 0x24)) +
                           (double)*(float *)(param_5 + 0x24));
    dVar5 = (double)(float)(param_4 * (double)(float)(dVar5 - (double)*(float *)(param_5 + 0x28)) +
                           (double)*(float *)(param_5 + 0x28));
    dVar3 = (double)(float)(param_4 * (double)(float)(dVar4 - (double)*(float *)(param_5 + 0x2c)) +
                           (double)*(float *)(param_5 + 0x2c));
    bVar1 = *(byte *)(iVar2 + 0x90);
    if (bVar1 < 4) {
      if (bVar1 < 2) {
        dVar6 = (double)FLOAT_803e3c74;
        dVar4 = FUN_80293900((double)(float)(dVar5 * dVar5 + (double)(float)(dVar3 * dVar3)));
        if (dVar4 != (double)FLOAT_803e3c74) {
          dVar4 = (double)(float)((double)*(float *)(iVar2 + 0x60) / dVar4);
          dVar5 = (double)(float)(dVar5 * dVar4);
          dVar3 = (double)(float)(dVar3 * dVar4);
        }
      }
      else {
        dVar3 = (double)FLOAT_803e3c74;
        dVar4 = FUN_80293900((double)(float)(dVar6 * dVar6 + (double)(float)(dVar5 * dVar5)));
        if (dVar4 != (double)FLOAT_803e3c74) {
          dVar4 = (double)(float)((double)*(float *)(iVar2 + 0x60) / dVar4);
          dVar6 = (double)(float)(dVar6 * dVar4);
          dVar5 = (double)(float)(dVar5 * dVar4);
        }
      }
    }
    else if (bVar1 == 6) {
      dVar4 = (double)(float)(dVar3 * (double)*(float *)(iVar2 + 0x84) +
                             (double)(float)(dVar6 * (double)*(float *)(iVar2 + 0x7c) +
                                            (double)(float)(dVar5 * (double)*(float *)(iVar2 + 0x80)
                                                           )));
      dVar6 = -(double)(float)(dVar4 * (double)*(float *)(iVar2 + 0x7c) - dVar6);
      dVar5 = -(double)(float)(dVar4 * (double)*(float *)(iVar2 + 0x80) - dVar5);
      dVar3 = -(double)(float)(dVar4 * (double)*(float *)(iVar2 + 0x84) - dVar3);
      dVar4 = FUN_80293900((double)(float)(dVar3 * dVar3 +
                                          (double)(float)(dVar6 * dVar6 +
                                                         (double)(float)(dVar5 * dVar5))));
      if (dVar4 != (double)FLOAT_803e3c74) {
        dVar4 = (double)(float)((double)*(float *)(iVar2 + 0x60) / dVar4);
        dVar6 = (double)(float)(dVar6 * dVar4);
        dVar5 = (double)(float)(dVar5 * dVar4);
        dVar3 = (double)(float)(dVar3 * dVar4);
      }
    }
    else if (bVar1 < 6) {
      dVar5 = (double)FLOAT_803e3c74;
      dVar4 = FUN_80293900((double)(float)(dVar6 * dVar6 + (double)(float)(dVar3 * dVar3)));
      if (dVar4 != (double)FLOAT_803e3c74) {
        dVar4 = (double)(float)((double)*(float *)(iVar2 + 0x60) / dVar4);
        dVar6 = (double)(float)(dVar6 * dVar4);
        dVar3 = (double)(float)(dVar3 * dVar4);
      }
    }
    *(float *)(param_5 + 0x24) = (float)dVar6;
    *(float *)(param_5 + 0x28) = (float)dVar5;
    *(float *)(param_5 + 0x2c) = (float)dVar3;
  }
  return;
}

