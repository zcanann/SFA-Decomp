// Function: FUN_800628e4
// Entry: 800628e4
// Size: 332 bytes

int FUN_800628e4(int param_1,undefined4 param_2)

{
  int iVar1;
  int iVar2;
  undefined4 uVar3;
  undefined4 *puVar4;
  
  iVar1 = FUN_80022e24(param_2);
  *(int *)(param_1 + 100) = iVar1;
  puVar4 = *(undefined4 **)(param_1 + 100);
  iVar2 = *(int *)(param_1 + 0x50);
  if ((*(short *)(iVar2 + 0x4a) == -1) || (*(short *)(iVar2 + 0x48) == 2)) {
    if ((*(byte *)(iVar2 + 0x5f) & 4) == 0) {
      if ((*(byte *)(iVar2 + 0x5f) & 2) == 0) {
        uVar3 = FUN_8006c5c4();
        puVar4[1] = uVar3;
      }
      else {
        puVar4[1] = 0;
        puVar4[2] = 0;
      }
    }
    else {
      uVar3 = FUN_8006c54c();
      puVar4[1] = uVar3;
    }
  }
  else {
    uVar3 = FUN_800544a4(-(int)*(short *)(iVar2 + 0x4a),0);
    puVar4[1] = uVar3;
  }
  if (*(short *)(*(int *)(param_1 + 0x50) + 0x48) == 1) {
    puVar4[4] = 0;
  }
  else {
    puVar4[4] = 0xffffffff;
  }
  *puVar4 = **(undefined4 **)(param_1 + 0x50);
  puVar4[0xb] = *(undefined4 *)(*(int *)(param_1 + 0x50) + 0x88);
  puVar4[5] = FLOAT_803dced8;
  puVar4[6] = FLOAT_803db650;
  puVar4[7] = FLOAT_803dcedc;
  *(undefined2 *)((int)puVar4 + 0x36) = 0x4000;
  puVar4[0xc] = 4;
  *(undefined *)(puVar4 + 0xe) = 0x19;
  *(undefined *)((int)puVar4 + 0x39) = 0x4b;
  *(undefined *)((int)puVar4 + 0x3a) = 0x96;
  *(undefined *)((int)puVar4 + 0x3b) = 100;
  DAT_803db658 = 1;
  return iVar1 + 0x44;
}

