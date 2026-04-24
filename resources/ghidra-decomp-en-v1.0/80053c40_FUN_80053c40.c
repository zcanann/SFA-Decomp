// Function: FUN_80053c40
// Entry: 80053c40
// Size: 280 bytes

void FUN_80053c40(int param_1,undefined4 param_2)

{
  bool bVar1;
  double dVar2;
  
  bVar1 = 0 < (int)((uint)*(byte *)(param_1 + 0x1d) - (uint)*(byte *)(param_1 + 0x1c));
  FUN_8025a310(param_2,param_1 + *(int *)(param_1 + 0x50) + 0x60,*(undefined2 *)(param_1 + 10),
               *(undefined2 *)(param_1 + 0xc),0,*(undefined *)(param_1 + 0x17),
               *(undefined *)(param_1 + 0x18),bVar1);
  if (bVar1) {
    FUN_8025a584((double)(float)((double)CONCAT44(0x43300000,(uint)*(byte *)(param_1 + 0x1c)) -
                                DOUBLE_803deba0),
                 (double)(float)((double)CONCAT44(0x43300000,*(byte *)(param_1 + 0x1d) ^ 0x80000000)
                                - DOUBLE_803deba8),(double)FLOAT_803deb98,param_2,
                 *(undefined *)(param_1 + 0x19),*(undefined *)(param_1 + 0x1a),0,0,0);
  }
  else {
    dVar2 = (double)FLOAT_803deb9c;
    FUN_8025a584(dVar2,dVar2,dVar2,param_2,*(undefined *)(param_1 + 0x19),
                 *(undefined *)(param_1 + 0x1a),0,0,0);
  }
  return;
}

