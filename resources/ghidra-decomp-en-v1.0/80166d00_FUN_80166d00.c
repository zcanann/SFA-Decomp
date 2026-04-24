// Function: FUN_80166d00
// Entry: 80166d00
// Size: 312 bytes

void FUN_80166d00(undefined4 param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4,
                 undefined4 param_5,char param_6)

{
  int iVar1;
  int iVar2;
  double dVar3;
  undefined8 uVar4;
  undefined auStack88 [48];
  float local_28;
  undefined4 local_24;
  float local_20;
  
  uVar4 = FUN_802860d8();
  iVar1 = (int)((ulonglong)uVar4 >> 0x20);
  iVar2 = *(int *)(*(int *)(iVar1 + 0xb8) + 0x40c);
  if ((param_6 != '\0') && (*(int *)(iVar1 + 0xf4) == 0)) {
    if ((*(char *)(iVar2 + 0x90) == '\x06') && ((*(byte *)(iVar2 + 0x92) >> 3 & 1) != 0)) {
      if ((*(byte *)(iVar2 + 0x92) >> 2 & 1) == 0) {
        FUN_80166e38(iVar2 + 4,iVar1 + 0x24,iVar2 + 0x7c);
      }
      dVar3 = (double)*(float *)(iVar1 + 8);
      FUN_80021858(dVar3,dVar3,dVar3,auStack88);
      FUN_800222e4(auStack88,iVar2 + 4,auStack88);
      local_28 = *(float *)(iVar1 + 0xc) - FLOAT_803dcdd8;
      local_24 = *(undefined4 *)(iVar1 + 0x10);
      local_20 = *(float *)(iVar1 + 0x14) - FLOAT_803dcddc;
      FUN_8003b950(auStack88);
      FUN_8003b8f4((double)FLOAT_803e2ff4,iVar1,(int)uVar4,param_3,param_4,param_5);
      FUN_8003b950(0);
    }
    else {
      FUN_8003b8f4((double)FLOAT_803e2ff4,iVar1,(int)uVar4,param_3,param_4,param_5);
    }
  }
  FUN_80286124();
  return;
}

