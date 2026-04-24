// Function: FUN_8016a170
// Entry: 8016a170
// Size: 552 bytes

void FUN_8016a170(uint param_1)

{
  uint uVar1;
  int *piVar2;
  undefined4 in_r9;
  undefined4 in_r10;
  int *piVar3;
  double dVar4;
  double dVar5;
  undefined8 in_f4;
  undefined8 in_f5;
  undefined8 in_f6;
  undefined8 in_f7;
  undefined8 in_f8;
  
  piVar3 = *(int **)(param_1 + 0xb8);
  *(undefined4 *)(param_1 + 0xf4) = 400;
  FUN_80035ff8(param_1);
  *(undefined *)(param_1 + 0x36) = 0xff;
  FUN_8000bb38(param_1,0x278);
  *(ushort *)(param_1 + 0xb0) = *(ushort *)(param_1 + 0xb0) | 0x2000;
  if (*piVar3 == 0) {
    piVar2 = FUN_8001f58c(param_1,'\x01');
    *piVar3 = (int)piVar2;
    if (*piVar3 != 0) {
      FUN_8001dbf0(*piVar3,2);
    }
  }
  if ((int *)*piVar3 != (int *)0x0) {
    dVar4 = (double)FLOAT_803e3d90;
    dVar5 = dVar4;
    FUN_8001de4c(dVar4,dVar4,dVar4,(int *)*piVar3);
    if (*(short *)(param_1 + 0x46) == 0x869) {
      FUN_8001dbb4(*piVar3,0xff,0xc0,0,0xff);
      FUN_8001dadc(*piVar3,0xff,0xc0,0,0xff);
      FUN_8001d7f4((double)(float)((double)FLOAT_803e3da0 *
                                  (double)(FLOAT_803e3da4 * *(float *)(param_1 + 8))),
                   (double)FLOAT_803e3da0,dVar5,in_f4,in_f5,in_f6,in_f7,in_f8,*piVar3,0,0xff,0xc0,0,
                   0x7f,in_r9,in_r10);
      FUN_8001db7c(*piVar3,0xff,0xd2,0,0xff);
    }
    else {
      FUN_8001dbb4(*piVar3,0,0xff,0,0xff);
      FUN_8001dadc(*piVar3,0,0xff,0,0xff);
      FUN_8001d7f4((double)(FLOAT_803e3da4 * *(float *)(param_1 + 8)),dVar4,dVar5,in_f4,in_f5,in_f6,
                   in_f7,in_f8,*piVar3,0,0,0xff,0,0x28,in_r9,in_r10);
      FUN_8001db7c(*piVar3,0,0xff,0,0xff);
    }
    uVar1 = (uint)(FLOAT_803e3da4 * *(float *)(param_1 + 8));
    FUN_8001dcfc((double)(float)((double)CONCAT44(0x43300000,uVar1 ^ 0x80000000) - DOUBLE_803e3d80),
                 (double)(float)((double)CONCAT44(0x43300000,uVar1 + 0x28 ^ 0x80000000) -
                                DOUBLE_803e3d80),*piVar3);
    FUN_8001dc18(*piVar3,1);
    FUN_8001dc30((double)FLOAT_803e3d78,*piVar3,'\x01');
    FUN_8001d6e4(*piVar3,1,3);
  }
  return;
}

