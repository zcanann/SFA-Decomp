// Function: FUN_8021d6e8
// Entry: 8021d6e8
// Size: 292 bytes

undefined4 FUN_8021d6e8(int param_1,int param_2)

{
  float fVar1;
  undefined4 uVar2;
  int iVar3;
  
  fVar1 = FLOAT_803e6aa8;
  iVar3 = *(int *)(param_1 + 0xb8);
  if (*(char *)(param_2 + 0x27a) != '\0') {
    *(float *)(param_2 + 0x294) = FLOAT_803e6aa8;
    *(float *)(param_2 + 0x284) = fVar1;
    *(float *)(param_2 + 0x280) = fVar1;
    *(float *)(param_1 + 0x24) = fVar1;
    *(float *)(param_1 + 0x28) = fVar1;
    *(float *)(param_1 + 0x2c) = fVar1;
    FUN_80035ea4();
    (**(code **)(*DAT_803dca68 + 0x60))();
    *(byte *)(iVar3 + 0xc49) = *(byte *)(iVar3 + 0xc49) & 0xfe;
    *(byte *)(iVar3 + 0xc49) = *(byte *)(iVar3 + 0xc49) & 0xbf;
    *(undefined *)(iVar3 + 0xc4b) = 5;
    *(float *)(param_2 + 0x2a0) = FLOAT_803e6aac;
    *(byte *)(iVar3 + 0x9fd) = *(byte *)(iVar3 + 0x9fd) & 0xfe;
    FUN_80036fa4(param_1,10);
  }
  if ((*(char *)(param_2 + 0x346) != '\0') && (*(short *)(param_1 + 0xa0) != 0)) {
    FUN_80030334((double)FLOAT_803e6aa8,param_1,0,0);
    *(float *)(param_2 + 0x2a0) = FLOAT_803e6ac8;
  }
  iVar3 = FUN_800221a0(0,1000);
  if (iVar3 == 0) {
    uVar2 = 9;
  }
  else {
    uVar2 = 0;
  }
  return uVar2;
}

