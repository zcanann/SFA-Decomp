// Function: FUN_80063254
// Entry: 80063254
// Size: 656 bytes

/* WARNING: Removing unreachable block (ram,0x800634c0) */
/* WARNING: Removing unreachable block (ram,0x800634b8) */
/* WARNING: Removing unreachable block (ram,0x800634b0) */
/* WARNING: Removing unreachable block (ram,0x800634a8) */
/* WARNING: Removing unreachable block (ram,0x800634a0) */
/* WARNING: Removing unreachable block (ram,0x80063498) */
/* WARNING: Removing unreachable block (ram,0x80063490) */
/* WARNING: Removing unreachable block (ram,0x80063294) */
/* WARNING: Removing unreachable block (ram,0x8006328c) */
/* WARNING: Removing unreachable block (ram,0x80063284) */
/* WARNING: Removing unreachable block (ram,0x8006327c) */
/* WARNING: Removing unreachable block (ram,0x80063274) */
/* WARNING: Removing unreachable block (ram,0x8006326c) */
/* WARNING: Removing unreachable block (ram,0x80063264) */

undefined4
FUN_80063254(double param_1,double param_2,double param_3,float *param_4,float *param_5,char param_6
            )

{
  float fVar1;
  double dVar2;
  double dVar3;
  double dVar4;
  double dVar5;
  double dVar6;
  double dVar7;
  double dVar8;
  
  dVar2 = (double)FLOAT_803df934;
  if (dVar2 != param_3) {
    dVar5 = (double)*param_4;
    dVar4 = (double)(float)(dVar5 - param_1);
    dVar3 = (double)(float)((double)*param_5 - param_2);
    dVar6 = -(double)(float)(param_3 * param_3 -
                            (double)((float)(dVar4 * dVar4) + (float)(dVar3 * dVar3)));
    if (dVar2 <= dVar6) {
      dVar8 = (double)(float)((double)param_4[1] - dVar5);
      dVar7 = (double)(float)((double)param_5[1] - (double)*param_5);
      dVar5 = (double)(float)(dVar8 * dVar8 + (double)(float)(dVar7 * dVar7));
      if (dVar2 < dVar5) {
        dVar4 = (double)(FLOAT_803df938 * (float)(dVar8 * dVar4 + (double)(float)(dVar7 * dVar3)));
        dVar3 = (double)(float)(dVar4 * dVar4 -
                               (double)(float)((double)(float)((double)FLOAT_803df93c * dVar5) *
                                              dVar6));
        if (dVar2 <= dVar3) {
          dVar3 = FUN_80293900(dVar3);
          dVar2 = (double)((float)(-dVar4 + dVar3) / (float)((double)FLOAT_803df938 * dVar5));
          dVar3 = (double)((float)(-dVar4 - dVar3) / (float)((double)FLOAT_803df938 * dVar5));
          if (dVar2 < (double)FLOAT_803df934) {
            dVar2 = (double)FLOAT_803df940;
          }
          if (dVar3 < (double)FLOAT_803df934) {
            dVar3 = (double)FLOAT_803df940;
          }
          if (dVar3 < dVar2) {
            dVar2 = dVar3;
          }
          if (((double)FLOAT_803df934 <= dVar2) && (dVar2 <= (double)FLOAT_803df944)) {
            FLOAT_803ddbd8 = (float)dVar2;
            if (param_6 != '\0') {
              dVar3 = (double)(float)(dVar2 * dVar8 + (double)*param_4);
              dVar2 = (double)(float)(dVar2 * dVar7 + (double)*param_5);
              dVar4 = (double)(float)((double)(float)(dVar3 - param_1) / param_3);
              dVar5 = (double)(float)((double)(float)(dVar2 - param_2) / param_3);
              fVar1 = -(float)(dVar3 * dVar4 + (double)(float)(dVar2 * dVar5));
              dVar2 = (double)(fVar1 + (float)(dVar4 * (double)param_4[1] +
                                              (double)(float)(dVar5 * (double)param_5[1])));
              param_4[1] = -(float)(dVar2 * dVar4 - (double)param_4[1]);
              param_5[1] = -(float)(dVar2 * dVar5 - (double)param_5[1]);
              dVar2 = (double)FLOAT_803df948;
              while ((double)(fVar1 + (float)((double)param_4[1] * dVar4 +
                                             (double)(float)((double)param_5[1] * dVar5))) < dVar2)
              {
                param_4[1] = param_4[1] + (float)(dVar2 * dVar4);
                param_5[1] = param_5[1] + (float)(dVar2 * dVar5);
              }
            }
            return 1;
          }
        }
      }
    }
    else if (param_6 != '\0') {
      param_4[1] = (float)(dVar5 + (double)FLOAT_803ddbd4);
      param_5[1] = *param_5 + FLOAT_803ddbd0;
    }
  }
  return 0;
}

