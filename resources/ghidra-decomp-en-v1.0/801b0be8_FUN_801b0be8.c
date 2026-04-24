// Function: FUN_801b0be8
// Entry: 801b0be8
// Size: 492 bytes

void FUN_801b0be8(int param_1,int param_2)

{
  int iVar1;
  uint uVar2;
  int *piVar3;
  
  *(code **)(param_1 + 0xbc) = FUN_801b0670;
  FUN_80037200(param_1,0x31);
  piVar3 = *(int **)(param_1 + 0xb8);
  *(undefined *)(piVar3 + 8) = 0;
  *(char *)(piVar3 + 6) = (char)*(undefined2 *)(param_2 + 0x1a);
  *(char *)(piVar3 + 7) = (char)*(undefined2 *)(param_2 + 0x1c);
  *(undefined *)((int)piVar3 + 0x1e) = *(undefined *)(piVar3 + 7);
  iVar1 = FUN_8001ffb4((int)*(short *)(param_2 + 0x1e));
  if (iVar1 != 0) {
    *(undefined *)((int)piVar3 + 0x1a) = 1;
    *(undefined *)((int)piVar3 + 0x1d) = 1;
  }
  *(ushort *)(param_1 + 0xb0) = *(ushort *)(param_1 + 0xb0) | 0x2000;
  piVar3[4] = (int)FLOAT_803e482c;
  piVar3[5] = (int)FLOAT_803e4820;
  if (*piVar3 == 0) {
    iVar1 = FUN_8001f4c8(param_1,1);
    *piVar3 = iVar1;
  }
  if (*piVar3 != 0) {
    FUN_8001db2c(*piVar3,2);
    FUN_8001daf0(*piVar3,0xff,0x7f,0,0xff);
    FUN_8001da18(*piVar3,0xff,0x7f,0,0xff);
    uVar2 = (int)(FLOAT_803e4830 * *(float *)(param_1 + 8)) ^ 0x80000000;
    FUN_8001dc38((double)(float)((double)CONCAT44(0x43300000,uVar2) - DOUBLE_803e4840),
                 (double)(FLOAT_803e4834 +
                         (float)((double)CONCAT44(0x43300000,uVar2) - DOUBLE_803e4840)),*piVar3);
    FUN_8001db6c((double)FLOAT_803e4828,*piVar3,1);
    FUN_8001dd88((double)FLOAT_803e4828,(double)FLOAT_803e4838,(double)FLOAT_803e4828,*piVar3);
    FUN_8001d620(*piVar3,1,3);
    FUN_8001dab8(*piVar3,0xff,0x5c,0,0xff);
    FUN_8001d730((double)(FLOAT_803e483c * *(float *)(param_1 + 8)),*piVar3,0,0xff,0x7f,0,0x87);
    FUN_8001d714((double)FLOAT_803e4834,*piVar3);
  }
  return;
}

