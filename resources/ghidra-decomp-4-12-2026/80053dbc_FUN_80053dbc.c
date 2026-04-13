// Function: FUN_80053dbc
// Entry: 80053dbc
// Size: 280 bytes

void FUN_80053dbc(int param_1,uint *param_2)

{
  bool bVar1;
  double dVar2;
  
  bVar1 = 0 < (int)((uint)*(byte *)(param_1 + 0x1d) - (uint)*(byte *)(param_1 + 0x1c));
  FUN_8025aa74(param_2,param_1 + *(int *)(param_1 + 0x50) + 0x60,(uint)*(ushort *)(param_1 + 10),
               (uint)*(ushort *)(param_1 + 0xc),0,(uint)*(byte *)(param_1 + 0x17),
               (uint)*(byte *)(param_1 + 0x18),bVar1);
  if (bVar1) {
    FUN_8025ace8((double)(float)((double)CONCAT44(0x43300000,(uint)*(byte *)(param_1 + 0x1c)) -
                                DOUBLE_803df820),
                 (double)(float)((double)CONCAT44(0x43300000,*(byte *)(param_1 + 0x1d) ^ 0x80000000)
                                - DOUBLE_803df828),(double)FLOAT_803df818,param_2,
                 (uint)*(byte *)(param_1 + 0x19),(uint)*(byte *)(param_1 + 0x1a),0,'\0',0);
  }
  else {
    dVar2 = (double)FLOAT_803df81c;
    FUN_8025ace8(dVar2,dVar2,dVar2,param_2,(uint)*(byte *)(param_1 + 0x19),
                 (uint)*(byte *)(param_1 + 0x1a),0,'\0',0);
  }
  return;
}

