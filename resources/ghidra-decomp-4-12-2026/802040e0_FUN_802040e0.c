// Function: FUN_802040e0
// Entry: 802040e0
// Size: 428 bytes

void FUN_802040e0(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9,int param_10,int param_11)

{
  uint uVar1;
  undefined4 uVar2;
  undefined4 uVar3;
  undefined4 uVar4;
  undefined4 uVar5;
  int iVar6;
  undefined4 *puVar7;
  int iVar8;
  
  iVar8 = *(int *)(param_9 + 0xb8);
  uVar5 = 6;
  if (param_11 != 0) {
    uVar5 = 7;
  }
  uVar2 = 0x10;
  uVar3 = 7;
  uVar4 = 0x10a;
  iVar6 = *DAT_803dd738;
  (**(code **)(iVar6 + 0x58))((double)FLOAT_803e6f94,param_9,param_10,iVar8);
  FUN_800372f8(param_9,3);
  *(undefined4 *)(param_9 + 0xbc) = 0;
  puVar7 = *(undefined4 **)(iVar8 + 0x40c);
  FUN_800033a8((int)puVar7,0,0x50);
  puVar7[2] = FLOAT_803e6f94;
  *puVar7 = &PTR_DAT_8032a154 + *(short *)(param_10 + 0x24) * 2;
  uVar1 = FUN_80022264(10,300);
  puVar7[3] = (float)((double)CONCAT44(0x43300000,uVar1 ^ 0x80000000) - DOUBLE_803e7000);
  *(byte *)(puVar7 + 0x11) =
       (byte)((*(byte *)(param_10 + 0x2b) & 1) << 5) | *(byte *)(puVar7 + 0x11) & 0xdf;
  *(byte *)(puVar7 + 0x11) = *(byte *)(puVar7 + 0x11) & 0xef | 0x10;
  puVar7[6] = 0;
  FUN_8003042c((double)FLOAT_803e6f40,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
               param_9,8,0,uVar2,uVar3,uVar4,uVar5,iVar6);
  *(byte *)(param_9 + 0xaf) = *(byte *)(param_9 + 0xaf) | 8;
  (**(code **)(*DAT_803dd70c + 0x14))(param_9,iVar8,3);
  *(undefined2 *)(iVar8 + 0x270) = 0;
  *(undefined *)(iVar8 + 0x25f) = 1;
  FUN_80036018(param_9);
  FUN_80037a5c(param_9,4);
  iVar8 = *(int *)(param_9 + 100);
  if (iVar8 != 0) {
    *(uint *)(iVar8 + 0x30) = *(uint *)(iVar8 + 0x30) | 0x4008;
  }
  return;
}

