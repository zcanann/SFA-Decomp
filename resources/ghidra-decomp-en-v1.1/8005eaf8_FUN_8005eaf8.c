// Function: FUN_8005eaf8
// Entry: 8005eaf8
// Size: 296 bytes

/* WARNING: Removing unreachable block (ram,0x8005ec10) */
/* WARNING: Removing unreachable block (ram,0x8005ec08) */
/* WARNING: Removing unreachable block (ram,0x8005ec00) */
/* WARNING: Removing unreachable block (ram,0x8005ebf8) */
/* WARNING: Removing unreachable block (ram,0x8005eb18) */
/* WARNING: Removing unreachable block (ram,0x8005eb10) */
/* WARNING: Removing unreachable block (ram,0x8005eb08) */
/* WARNING: Removing unreachable block (ram,0x8005eb00) */

undefined4
FUN_8005eaf8(double param_1,double param_2,double param_3,double param_4,double param_5,
            double param_6,float *param_7)

{
  byte bVar1;
  float *pfVar2;
  int iVar3;
  double dVar4;
  double dVar5;
  double dVar6;
  double dVar7;
  double dVar8;
  double dVar9;
  
  pfVar2 = (float *)&DAT_8038859c;
  iVar3 = 5;
  while( true ) {
    bVar1 = *(byte *)(pfVar2 + 4);
    dVar5 = param_1;
    dVar8 = param_2;
    if ((bVar1 & 1) != 0) {
      dVar5 = param_2;
      dVar8 = param_1;
    }
    dVar4 = param_3;
    dVar7 = param_4;
    if ((bVar1 & 2) != 0) {
      dVar4 = param_4;
      dVar7 = param_3;
    }
    dVar6 = param_6;
    dVar9 = param_5;
    if ((bVar1 & 4) != 0) {
      dVar6 = param_5;
      dVar9 = param_6;
    }
    if ((*param_7 +
         pfVar2[3] +
         (float)(dVar9 * (double)pfVar2[2] +
                (double)(float)(dVar5 * (double)*pfVar2 + (double)(float)(dVar4 * (double)pfVar2[1])
                               )) < FLOAT_803df84c) &&
       (*param_7 +
        pfVar2[3] +
        (float)(dVar6 * (double)pfVar2[2] +
               (double)(float)(dVar8 * (double)*pfVar2 + (double)(float)(dVar7 * (double)pfVar2[1]))
               ) < FLOAT_803df84c)) break;
    pfVar2 = pfVar2 + 5;
    param_7 = param_7 + 1;
    iVar3 = iVar3 + -1;
    if (iVar3 == 0) {
      return 1;
    }
  }
  return 0;
}

