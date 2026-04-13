// Function: FUN_801b119c
// Entry: 801b119c
// Size: 492 bytes

void FUN_801b119c(int param_1,int param_2)

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
  
  *(code **)(param_1 + 0xbc) = FUN_801b0c24;
  FUN_800372f8(param_1,0x31);
  piVar3 = *(int **)(param_1 + 0xb8);
  *(undefined *)(piVar3 + 8) = 0;
  *(char *)(piVar3 + 6) = (char)*(undefined2 *)(param_2 + 0x1a);
  *(char *)(piVar3 + 7) = (char)*(undefined2 *)(param_2 + 0x1c);
  *(undefined *)((int)piVar3 + 0x1e) = *(undefined *)(piVar3 + 7);
  uVar1 = FUN_80020078((int)*(short *)(param_2 + 0x1e));
  if (uVar1 != 0) {
    *(undefined *)((int)piVar3 + 0x1a) = 1;
    *(undefined *)((int)piVar3 + 0x1d) = 1;
  }
  *(ushort *)(param_1 + 0xb0) = *(ushort *)(param_1 + 0xb0) | 0x2000;
  piVar3[4] = (int)FLOAT_803e54c4;
  piVar3[5] = (int)FLOAT_803e54b8;
  if (*piVar3 == 0) {
    piVar2 = FUN_8001f58c(param_1,'\x01');
    *piVar3 = (int)piVar2;
  }
  if (*piVar3 != 0) {
    FUN_8001dbf0(*piVar3,2);
    FUN_8001dbb4(*piVar3,0xff,0x7f,0,0xff);
    FUN_8001dadc(*piVar3,0xff,0x7f,0,0xff);
    uVar1 = (int)(FLOAT_803e54c8 * *(float *)(param_1 + 8)) ^ 0x80000000;
    FUN_8001dcfc((double)(float)((double)CONCAT44(0x43300000,uVar1) - DOUBLE_803e54d8),
                 (double)(FLOAT_803e54cc +
                         (float)((double)CONCAT44(0x43300000,uVar1) - DOUBLE_803e54d8)),*piVar3);
    FUN_8001dc30((double)FLOAT_803e54c0,*piVar3,'\x01');
    dVar4 = (double)FLOAT_803e54c0;
    dVar5 = (double)FLOAT_803e54d0;
    FUN_8001de4c(dVar4,dVar5,dVar4,(int *)*piVar3);
    FUN_8001d6e4(*piVar3,1,3);
    FUN_8001db7c(*piVar3,0xff,0x5c,0,0xff);
    FUN_8001d7f4((double)(FLOAT_803e54d4 * *(float *)(param_1 + 8)),dVar5,dVar4,in_f4,in_f5,in_f6,
                 in_f7,in_f8,*piVar3,0,0xff,0x7f,0,0x87,in_r9,in_r10);
    FUN_8001d7d8((double)FLOAT_803e54cc,*piVar3);
  }
  return;
}

