// Function: FUN_801e86f4
// Entry: 801e86f4
// Size: 436 bytes

undefined4 FUN_801e86f4(undefined2 *param_1,undefined4 param_2,int param_3)

{
  undefined2 uVar1;
  int iVar2;
  double dVar3;
  
  iVar2 = *(int *)(param_1 + 0x5c);
  *(code **)(param_3 + 0xe8) = FUN_801e8660;
  *(ushort *)(param_3 + 0x6e) = *(ushort *)(param_3 + 0x6e) & 0xfffb;
  *(ushort *)(param_3 + 0x70) = *(ushort *)(param_3 + 0x70) & 0xfffb;
  if (*(int *)(*(int *)(param_1 + 0x3e) + *(char *)((int)param_1 + 0xad) * 4) != 0) {
    FUN_8002fa48((double)FLOAT_803e5a60,(double)FLOAT_803db414,param_1,0);
  }
  if (param_1[0x23] == 0x467) {
    if (FLOAT_803e5a30 < *(float *)(iVar2 + 0x40)) {
      *(float *)(iVar2 + 0x40) = *(float *)(iVar2 + 0x40) - FLOAT_803e5a30;
      if (*(byte *)(iVar2 + 0x68) < 4) {
        FUN_801f4d54(param_1,iVar2);
      }
      else {
        *(byte *)(iVar2 + 0x68) = *(byte *)(iVar2 + 0x68) + 1;
      }
      FUN_801f4ecc(param_1,iVar2);
    }
    dVar3 = (double)FUN_80010ee0((double)*(float *)(iVar2 + 0x40),iVar2 + 4,0);
    *(float *)(param_1 + 6) = (float)dVar3;
    dVar3 = (double)FUN_80010ee0((double)*(float *)(iVar2 + 0x40),iVar2 + 0x14,0);
    *(float *)(param_1 + 8) = (float)dVar3;
    dVar3 = (double)FUN_80010ee0((double)*(float *)(iVar2 + 0x40),iVar2 + 0x24,0);
    *(float *)(param_1 + 10) = (float)dVar3;
    *(float *)(iVar2 + 0x40) = *(float *)(iVar2 + 0x44) * FLOAT_803db414 + *(float *)(iVar2 + 0x40);
    uVar1 = FUN_800217c0((double)(*(float *)(param_1 + 6) - *(float *)(param_1 + 0x40)),
                         (double)(*(float *)(param_1 + 10) - *(float *)(param_1 + 0x44)));
    *param_1 = uVar1;
    (**(code **)(*DAT_803dca88 + 8))(param_1,0x19f,0,1,0xffffffff,0);
    (**(code **)(*DAT_803dca88 + 8))(param_1,0x1a0,0,1,0xffffffff,0);
  }
  return 0;
}

