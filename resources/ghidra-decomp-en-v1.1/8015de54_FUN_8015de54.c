// Function: FUN_8015de54
// Entry: 8015de54
// Size: 284 bytes

void FUN_8015de54(undefined8 param_1,undefined8 param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9,int param_10,int param_11)

{
  undefined4 uVar1;
  undefined4 uVar2;
  undefined4 uVar3;
  uint uVar4;
  int iVar5;
  int iVar6;
  double dVar7;
  
  iVar6 = *(int *)(param_9 + 0xb8);
  uVar4 = 6;
  if (param_11 != 0) {
    uVar4 = 7;
  }
  if ((*(byte *)(param_10 + 0x2b) & 0x20) == 0) {
    uVar4 = uVar4 | 8;
  }
  uVar1 = 0xe;
  uVar2 = 8;
  uVar3 = 0x102;
  iVar5 = *DAT_803dd738;
  (**(code **)(iVar5 + 0x58))((double)FLOAT_803e3a50,param_9,param_10,iVar6);
  *(undefined4 *)(param_9 + 0xbc) = 0;
  dVar7 = (double)FLOAT_803e39bc;
  if ((float)(dVar7 * (double)(float)((double)CONCAT44(0x43300000,(uint)*(ushort *)(iVar6 + 0x3fe))
                                     - DOUBLE_803e39a0)) < FLOAT_803e39ec) {
    *(undefined2 *)(iVar6 + 0x3fe) = 0x6e;
  }
  FUN_8003042c((double)FLOAT_803e39ac,dVar7,param_3,param_4,param_5,param_6,param_7,param_8,param_9,
               8,0,uVar1,uVar2,uVar3,uVar4,iVar5);
  *(byte *)(param_9 + 0xaf) = *(byte *)(param_9 + 0xaf) | 8;
  (**(code **)(*DAT_803dd70c + 0x14))(param_9,iVar6,0);
  *(undefined2 *)(iVar6 + 0x270) = 0;
  *(undefined *)(iVar6 + 0x25f) = 0;
  return;
}

