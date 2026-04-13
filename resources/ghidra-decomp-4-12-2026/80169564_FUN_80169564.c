// Function: FUN_80169564
// Entry: 80169564
// Size: 488 bytes

void FUN_80169564(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined4 param_9,undefined4 param_10,int param_11)

{
  double dVar1;
  int iVar2;
  uint uVar3;
  undefined4 uVar4;
  undefined4 uVar5;
  undefined4 uVar6;
  undefined4 uVar7;
  int iVar8;
  undefined4 *puVar9;
  int iVar10;
  undefined8 uVar11;
  
  uVar11 = FUN_80286840();
  iVar2 = (int)((ulonglong)uVar11 >> 0x20);
  iVar10 = *(int *)(iVar2 + 0xb8);
  uVar7 = 6;
  if (param_11 != 0) {
    uVar7 = 7;
  }
  uVar4 = 8;
  uVar5 = 6;
  uVar6 = 0;
  iVar8 = *DAT_803dd738;
  (**(code **)(iVar8 + 0x58))((double)FLOAT_803e3d60,iVar2,(int)uVar11,iVar10);
  *(undefined4 *)(iVar2 + 0xbc) = 0;
  puVar9 = *(undefined4 **)(iVar10 + 0x40c);
  FUN_8003042c((double)FLOAT_803e3cf8,param_2,param_3,param_4,param_5,param_6,param_7,param_8,iVar2,
               4,0x10,uVar4,uVar5,uVar6,uVar7,iVar8);
  *(float *)(iVar2 + 0x98) = FLOAT_803e3d14;
  *(byte *)(iVar2 + 0xaf) = *(byte *)(iVar2 + 0xaf) | 8;
  (**(code **)(*DAT_803dd70c + 0x14))(iVar2,iVar10,0);
  *(undefined2 *)(iVar10 + 0x270) = 0;
  *(float *)(iVar10 + 0x2a0) = FLOAT_803e3d14;
  *(float *)(iVar10 + 0x280) = FLOAT_803e3cf8;
  uVar7 = FUN_8002bac4();
  *(undefined4 *)(iVar10 + 0x2d0) = uVar7;
  *(undefined *)(iVar10 + 0x25f) = 0;
  FUN_80035ff8(iVar2);
  uVar3 = FUN_80022264(300,600);
  puVar9[0xd] = (float)((double)CONCAT44(0x43300000,uVar3 ^ 0x80000000) - DOUBLE_803e3d08);
  uVar3 = FUN_80022264(0,499);
  dVar1 = DOUBLE_803e3d08;
  puVar9[0xe] = (float)((double)CONCAT44(0x43300000,uVar3 ^ 0x80000000) - DOUBLE_803e3d08);
  puVar9[0xf] = FLOAT_803e3cf8;
  *puVar9 = 0;
  *(ushort *)(iVar2 + 0xb0) = *(ushort *)(iVar2 + 0xb0) | 0x2000;
  *(float *)(iVar2 + 8) =
       FLOAT_803e3d38 +
       (float)((double)CONCAT44(0x43300000,(int)*(char *)((int)uVar11 + 0x28) ^ 0x80000000) - dVar1)
       / FLOAT_803e3d3c;
  FUN_80035a6c(iVar2,(short)(int)(FLOAT_803e3d64 * *(float *)(iVar2 + 8)));
  if (param_11 == 0) {
    DAT_803de710 = FUN_80013ee8(0x5a);
  }
  FUN_8028688c();
  return;
}

