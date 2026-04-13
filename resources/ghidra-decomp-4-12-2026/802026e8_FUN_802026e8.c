// Function: FUN_802026e8
// Entry: 802026e8
// Size: 480 bytes

void FUN_802026e8(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)

{
  float fVar1;
  uint uVar2;
  uint uVar3;
  int iVar4;
  undefined4 in_r6;
  undefined4 in_r7;
  undefined4 in_r8;
  undefined4 in_r9;
  undefined4 in_r10;
  int iVar5;
  int iVar6;
  int iVar7;
  double dVar8;
  undefined8 uVar9;
  undefined auStack_28 [40];
  
  uVar9 = FUN_80286840();
  uVar2 = (uint)((ulonglong)uVar9 >> 0x20);
  iVar4 = (int)uVar9;
  iVar7 = *(int *)(uVar2 + 0xb8);
  iVar6 = *(int *)(uVar2 + 0x4c);
  iVar5 = *(int *)(iVar7 + 0x40c);
  *(undefined *)(iVar4 + 0x34d) = 0x11;
  fVar1 = FLOAT_803e6f40;
  if (*(char *)(iVar4 + 0x27a) != '\0') {
    *(float *)(iVar4 + 0x284) = FLOAT_803e6f40;
    *(float *)(iVar4 + 0x280) = fVar1;
    *(undefined4 *)(iVar4 + 0x2d0) = 0;
    *(undefined *)(iVar4 + 0x25f) = 1;
    *(undefined *)(iVar4 + 0x349) = 0;
    *(byte *)(uVar2 + 0xaf) = *(byte *)(uVar2 + 0xaf) | 8;
    FUN_80035ff8(uVar2);
    uVar9 = FUN_8003709c(uVar2,3);
    if (*(int *)(iVar5 + 0x18) != 0) {
      in_r6 = 0x10;
      FUN_800379bc(uVar9,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                   *(int *)(iVar5 + 0x18),0x11,uVar2,0x10,in_r7,in_r8,in_r9,in_r10);
      *(undefined2 *)(iVar5 + 0x1c) = 0xffff;
      *(undefined4 *)(iVar5 + 0x18) = 0;
    }
  }
  if (*(char *)(iVar4 + 0x27a) != '\0') {
    FUN_8003042c((double)FLOAT_803e6f40,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                 uVar2,1,0,in_r6,in_r7,in_r8,in_r9,in_r10);
    *(undefined *)(iVar4 + 0x346) = 0;
  }
  *(float *)(iVar4 + 0x2a0) = FLOAT_803e6fcc;
  dVar8 = (double)*(float *)(uVar2 + 0x98);
  if ((double)FLOAT_803e6fd0 < dVar8) {
    FUN_80020000((int)*(short *)(iVar6 + 0x18));
    if (*(int *)(iVar6 + 0x14) == -1) {
      FUN_8002cc9c(dVar8,param_2,param_3,param_4,param_5,param_6,param_7,param_8,uVar2);
      goto LAB_802028b4;
    }
    while (uVar3 = FUN_800138d4(*(short **)(iVar5 + 0x24)), uVar3 == 0) {
      FUN_80013900(*(short **)(iVar5 + 0x24),(uint)auStack_28);
    }
    if (*(short *)(iVar6 + 0x2c) == 0) {
      (**(code **)(*DAT_803dd72c + 100))((double)FLOAT_803e6fd4,*(undefined4 *)(iVar6 + 0x14));
    }
    *(byte *)(iVar7 + 0x404) = *(byte *)(iVar7 + 0x404) | *(byte *)(iVar6 + 0x2b);
  }
  (**(code **)(*DAT_803dd70c + 0x34))(uVar2,iVar4,0,2,&DAT_8032a274);
  (**(code **)(*DAT_803dd70c + 0x34))(uVar2,iVar4,7,0,&DAT_8032a280);
LAB_802028b4:
  FUN_8028688c();
  return;
}

