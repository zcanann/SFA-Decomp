// Function: FUN_80062a60
// Entry: 80062a60
// Size: 332 bytes

int FUN_80062a60(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                int param_9,uint param_10)

{
  uint uVar1;
  int iVar2;
  undefined4 uVar3;
  undefined4 *puVar4;
  
  uVar1 = FUN_80022ee8(param_10);
  *(uint *)(param_9 + 100) = uVar1;
  puVar4 = *(undefined4 **)(param_9 + 100);
  iVar2 = *(int *)(param_9 + 0x50);
  if ((*(short *)(iVar2 + 0x4a) == -1) || (*(short *)(iVar2 + 0x48) == 2)) {
    if ((*(byte *)(iVar2 + 0x5f) & 4) == 0) {
      if ((*(byte *)(iVar2 + 0x5f) & 2) == 0) {
        uVar3 = FUN_8006c740();
        puVar4[1] = uVar3;
      }
      else {
        puVar4[1] = 0;
        puVar4[2] = 0;
      }
    }
    else {
      iVar2 = FUN_8006c6c8();
      puVar4[1] = iVar2;
    }
  }
  else {
    uVar3 = FUN_80054620(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
    puVar4[1] = uVar3;
  }
  if (*(short *)(*(int *)(param_9 + 0x50) + 0x48) == 1) {
    puVar4[4] = 0;
  }
  else {
    puVar4[4] = 0xffffffff;
  }
  *puVar4 = **(undefined4 **)(param_9 + 0x50);
  puVar4[0xb] = *(undefined4 *)(*(int *)(param_9 + 0x50) + 0x88);
  puVar4[5] = FLOAT_803ddb58;
  puVar4[6] = FLOAT_803dc2b0;
  puVar4[7] = FLOAT_803ddb5c;
  *(undefined2 *)((int)puVar4 + 0x36) = 0x4000;
  puVar4[0xc] = 4;
  *(undefined *)(puVar4 + 0xe) = 0x19;
  *(undefined *)((int)puVar4 + 0x39) = 0x4b;
  *(undefined *)((int)puVar4 + 0x3a) = 0x96;
  *(undefined *)((int)puVar4 + 0x3b) = 100;
  DAT_803dc2b8 = 1;
  return uVar1 + 0x44;
}

