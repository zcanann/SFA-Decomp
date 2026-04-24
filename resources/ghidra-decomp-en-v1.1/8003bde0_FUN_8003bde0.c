// Function: FUN_8003bde0
// Entry: 8003bde0
// Size: 336 bytes

/* WARNING: Removing unreachable block (ram,0x8003bf0c) */
/* WARNING: Removing unreachable block (ram,0x8003bf04) */
/* WARNING: Removing unreachable block (ram,0x8003bdf8) */
/* WARNING: Removing unreachable block (ram,0x8003bdf0) */

undefined4 FUN_8003bde0(float *param_1,undefined2 *param_2,undefined2 *param_3,undefined2 *param_4)

{
  float fVar1;
  int iVar2;
  undefined4 uVar3;
  double dVar4;
  double dVar5;
  double dVar6;
  double dVar7;
  float local_78 [19];
  
  iVar2 = FUN_8003bc7c(param_1,local_78);
  if (iVar2 == 0) {
    uVar3 = 0;
  }
  else {
    dVar4 = (double)FUN_802926a4();
    if ((double)FLOAT_803df688 <= dVar4) {
      dVar5 = (double)FUN_80292b24();
      dVar6 = (double)FLOAT_803df684;
      dVar5 = (double)(float)(dVar5 - dVar6);
    }
    else if (dVar4 <= (double)FLOAT_803df68c) {
      dVar5 = (double)FUN_80292b24();
      dVar6 = (double)FLOAT_803df684;
      dVar5 = (double)(float)(dVar6 - dVar5);
    }
    else {
      dVar5 = (double)FUN_80292b24();
      dVar6 = (double)FUN_80292b24();
    }
    fVar1 = FLOAT_803df694;
    dVar7 = (double)FLOAT_803df690;
    *param_4 = (short)(int)((float)(dVar7 * dVar6) / FLOAT_803df694);
    *param_3 = (short)(int)((float)(dVar7 * dVar4) / fVar1);
    *param_2 = (short)(int)((float)(dVar7 * dVar5) / fVar1);
    uVar3 = 1;
  }
  return uVar3;
}

