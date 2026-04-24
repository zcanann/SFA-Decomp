// Function: FUN_80169cc4
// Entry: 80169cc4
// Size: 552 bytes

void FUN_80169cc4(int param_1)

{
  uint uVar1;
  int iVar2;
  int *piVar3;
  double dVar4;
  
  piVar3 = *(int **)(param_1 + 0xb8);
  *(undefined4 *)(param_1 + 0xf4) = 400;
  FUN_80035f00();
  *(undefined *)(param_1 + 0x36) = 0xff;
  FUN_8000bb18(param_1,0x278);
  *(ushort *)(param_1 + 0xb0) = *(ushort *)(param_1 + 0xb0) | 0x2000;
  if (*piVar3 == 0) {
    iVar2 = FUN_8001f4c8(param_1,1);
    *piVar3 = iVar2;
    if (*piVar3 != 0) {
      FUN_8001db2c(*piVar3,2);
    }
  }
  if (*piVar3 != 0) {
    dVar4 = (double)FLOAT_803e30f8;
    FUN_8001dd88(dVar4,dVar4,dVar4);
    if (*(short *)(param_1 + 0x46) == 0x869) {
      FUN_8001daf0(*piVar3,0xff,0xc0,0,0xff);
      FUN_8001da18(*piVar3,0xff,0xc0,0,0xff);
      FUN_8001d730((double)(FLOAT_803e3108 * FLOAT_803e310c * *(float *)(param_1 + 8)),*piVar3,0,
                   0xff,0xc0,0,0x7f);
      FUN_8001dab8(*piVar3,0xff,0xd2,0,0xff);
    }
    else {
      FUN_8001daf0(*piVar3,0,0xff,0,0xff);
      FUN_8001da18(*piVar3,0,0xff,0,0xff);
      FUN_8001d730((double)(FLOAT_803e310c * *(float *)(param_1 + 8)),*piVar3,0,0,0xff,0,0x28);
      FUN_8001dab8(*piVar3,0,0xff,0,0xff);
    }
    uVar1 = (uint)(FLOAT_803e310c * *(float *)(param_1 + 8));
    FUN_8001dc38((double)(float)((double)CONCAT44(0x43300000,uVar1 ^ 0x80000000) - DOUBLE_803e30e8),
                 (double)(float)((double)CONCAT44(0x43300000,uVar1 + 0x28 ^ 0x80000000) -
                                DOUBLE_803e30e8),*piVar3);
    FUN_8001db54(*piVar3,1);
    FUN_8001db6c((double)FLOAT_803e30e0,*piVar3,1);
    FUN_8001d620(*piVar3,1,3);
  }
  return;
}

