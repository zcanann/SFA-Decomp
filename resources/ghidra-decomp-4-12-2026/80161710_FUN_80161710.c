// Function: FUN_80161710
// Entry: 80161710
// Size: 516 bytes

/* WARNING: Removing unreachable block (ram,0x801618f4) */
/* WARNING: Removing unreachable block (ram,0x801618ec) */
/* WARNING: Removing unreachable block (ram,0x80161728) */
/* WARNING: Removing unreachable block (ram,0x80161720) */

undefined4 FUN_80161710(short *param_1,int param_2)

{
  short sVar1;
  float fVar2;
  uint uVar3;
  undefined4 uVar4;
  int iVar5;
  double dVar6;
  double dVar7;
  
  iVar5 = *(int *)(param_2 + 0x2d0);
  if (iVar5 == 0) {
    (**(code **)(*DAT_803dd70c + 0x14))(param_1,param_2,0);
    uVar4 = 1;
  }
  else {
    if (*(short *)(param_2 + 0x274) != 6) {
      dVar7 = (double)(*(float *)(param_1 + 6) - *(float *)(iVar5 + 0xc));
      dVar6 = (double)(*(float *)(param_1 + 10) - *(float *)(iVar5 + 0x14));
      iVar5 = FUN_80021884();
      uVar3 = iVar5 - *param_1 & 0xffff;
      if ((uVar3 < 0x4001) || (fVar2 = FLOAT_803e3b48, 0xbfff < uVar3)) {
        dVar6 = FUN_80293900((double)(float)(dVar7 * dVar7 + (double)(float)(dVar6 * dVar6)));
        fVar2 = (float)(dVar6 - (double)FLOAT_803e3b4c);
      }
      dVar7 = (double)fVar2;
      dVar6 = dVar7;
      if (dVar7 < (double)FLOAT_803e3b50) {
        dVar6 = -dVar7;
      }
      if (((double)FLOAT_803e3b54 <= dVar6) ||
         ((*(short *)(param_2 + 0x274) != 1 &&
          ((*(short *)(param_2 + 0x274) != 5 || (*(char *)(param_2 + 0x346) == '\0')))))) {
        sVar1 = *(short *)(param_2 + 0x274);
        if (sVar1 != 1) {
          if ((((double)FLOAT_803e3b58 < dVar7) && (sVar1 != 4)) &&
             ((sVar1 != 5 || (*(char *)(param_2 + 0x346) != '\0')))) {
            (**(code **)(*DAT_803dd70c + 0x14))(param_1,param_2,1);
          }
          if (dVar7 < (double)FLOAT_803e3b5c) {
            (**(code **)(*DAT_803dd70c + 0x14))(param_1,param_2,1);
          }
        }
      }
      else {
        (**(code **)(*DAT_803dd70c + 0x14))(param_1,param_2,6);
      }
      if (*(short *)(param_2 + 0x274) == 1) {
        fVar2 = FLOAT_803e3b64;
        if ((double)FLOAT_803e3b50 < dVar7) {
          fVar2 = FLOAT_803e3b60;
        }
        *(float *)(param_2 + 0x2a0) = fVar2;
      }
    }
    uVar4 = 0;
  }
  return uVar4;
}

