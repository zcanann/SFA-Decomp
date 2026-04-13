// Function: FUN_80060a70
// Entry: 80060a70
// Size: 324 bytes

void FUN_80060a70(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9,int param_10,undefined4 param_11,undefined4 param_12,
                 undefined4 param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16)

{
  int iVar1;
  short *psVar2;
  int iVar3;
  int iVar4;
  uint uVar5;
  uint uVar6;
  
  uVar6 = *(uint *)(DAT_803ddb00 + param_10 * 4);
  uVar5 = *(int *)(DAT_803ddb00 + param_10 * 4 + 4) - uVar6;
  if (0 < (int)uVar5) {
    iVar1 = FUN_80023d8c(uVar5,5);
    *(int *)(param_9 + 0x70) = iVar1;
    FUN_800490c4(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0x28,
                 *(undefined4 *)(param_9 + 0x70),uVar6,uVar5,param_13,param_14,param_15,param_16);
  }
  *(short *)(param_9 + 0x9c) = (short)(uVar5 / 0x14);
  iVar1 = 0;
  for (iVar4 = 0; iVar4 < (int)(uint)*(ushort *)(param_9 + 0x9c); iVar4 = iVar4 + 1) {
    psVar2 = (short *)(*(int *)(param_9 + 0x70) + iVar1);
    if ((((*psVar2 < 0) || (psVar2[1] < 0)) || (0x280 < *psVar2)) || (0x280 < psVar2[1])) {
      *(undefined *)((int)psVar2 + 0xf) = 0x40;
    }
    iVar3 = *(int *)(param_9 + 0x70) + iVar1;
    if (((*(short *)(iVar3 + 8) < 0) || (*(short *)(iVar3 + 10) < 0)) ||
       ((0x280 < *(short *)(iVar3 + 8) || (0x280 < *(short *)(iVar3 + 10))))) {
      *(undefined *)(iVar3 + 0xf) = 0x40;
    }
    iVar1 = iVar1 + 0x14;
  }
  *(undefined4 *)(param_9 + 0x74) = 0;
  *(undefined2 *)(param_9 + 0x9e) = 0;
  *(ushort *)(param_9 + 4) = *(ushort *)(param_9 + 4) & 0xffbf;
  return;
}

