// Function: FUN_80220c74
// Entry: 80220c74
// Size: 260 bytes

void FUN_80220c74(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 uint param_9,undefined4 param_10,undefined4 param_11,undefined4 param_12,
                 undefined4 param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16)

{
  byte bVar1;
  uint uVar2;
  undefined4 *puVar3;
  int iVar4;
  int iVar5;
  byte *pbVar6;
  
  pbVar6 = *(byte **)(param_9 + 0xb8);
  iVar5 = *(int *)(param_9 + 0x4c);
  uVar2 = FUN_80020078((int)*(short *)(iVar5 + 0x20));
  if (uVar2 != 0) {
    bVar1 = *pbVar6;
    if (-1 < (char)bVar1) {
      *pbVar6 = bVar1 & 0x7f | 0x80;
      FUN_8000bb38(param_9,0x30c);
    }
    puVar3 = (undefined4 *)FUN_800395a4(param_9,0);
    if (puVar3 != (undefined4 *)0x0) {
      *puVar3 = 0x100;
    }
    iVar4 = FUN_800395a4(param_9,0);
    if ((iVar4 != 0) &&
       (*(ushort *)(iVar4 + 10) =
             *(short *)(iVar4 + 10) + (short)DAT_803dcfe8 * (ushort)DAT_803dc070,
       *(short *)(iVar4 + 10) < -0x1000)) {
      *(undefined2 *)(iVar4 + 10) = 0;
    }
  }
  uVar2 = FUN_80020078((int)*(short *)(iVar5 + 0x1e));
  if (uVar2 != 0) {
    FUN_8003042c((double)FLOAT_803e7848,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                 param_9,0,0,param_12,param_13,param_14,param_15,param_16);
  }
  return;
}

