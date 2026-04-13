// Function: FUN_80247944
// Entry: 80247944
// Size: 260 bytes

/* WARNING: Removing unreachable block (ram,0x80247a14) */
/* WARNING: Removing unreachable block (ram,0x80247a10) */
/* WARNING: Removing unreachable block (ram,0x80247a0c) */
/* WARNING: Removing unreachable block (ram,0x80247a04) */
/* WARNING: Removing unreachable block (ram,0x802479fc) */
/* WARNING: Removing unreachable block (ram,0x802479f4) */
/* WARNING: Removing unreachable block (ram,0x802479b0) */

void FUN_80247944(double param_1,float *param_2,float *param_3)

{
  double dVar1;
  double dVar2;
  double dVar3;
  double dVar4;
  double dVar5;
  double dVar6;
  double dVar7;
  double dVar8;
  double dVar9;
  float local_44;
  float fStack_40;
  float local_3c;
  
  dVar6 = (double)FLOAT_803e82b4;
  dVar1 = FUN_80295144(param_1);
  dVar2 = FUN_80294fb0(param_1);
  dVar7 = (double)(float)((double)FLOAT_803e82b0 - dVar2);
  FUN_80247ef8(param_3,&local_44);
  dVar5 = (double)local_44;
  dVar9 = (double)fStack_40;
  dVar3 = (double)local_3c;
  dVar4 = dVar5 * dVar7;
  dVar8 = dVar9 * dVar7 * dVar3;
  param_2[2] = (float)(dVar4 * dVar3 + dVar9 * dVar1);
  param_2[3] = (float)dVar6;
  *param_2 = (float)(dVar4 * dVar5 + dVar2);
  param_2[1] = -(float)(dVar3 * dVar1 - dVar4 * dVar9);
  param_2[4] = (float)(dVar3 * dVar1 + dVar4 * dVar9);
  param_2[5] = (float)(dVar2 + dVar9 * dVar7 * dVar9);
  param_2[6] = (float)(-(dVar5 * dVar1) + dVar8);
  param_2[7] = (float)dVar6;
  param_2[8] = (float)(dVar4 * dVar3 + -(dVar9 * dVar1));
  param_2[9] = (float)(dVar5 * dVar1 + dVar8);
  param_2[10] = (float)(dVar3 * dVar7 * dVar3 + dVar2);
  param_2[0xb] = (float)dVar6;
  return;
}

