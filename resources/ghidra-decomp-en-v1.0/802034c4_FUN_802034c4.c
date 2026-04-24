// Function: FUN_802034c4
// Entry: 802034c4
// Size: 368 bytes

void FUN_802034c4(undefined4 param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4,
                 undefined4 param_5,char param_6)

{
  int iVar1;
  int iVar2;
  int iVar3;
  undefined8 uVar4;
  
  uVar4 = FUN_802860d4();
  iVar1 = (int)((ulonglong)uVar4 >> 0x20);
  iVar2 = *(int *)(iVar1 + 0xb8);
  iVar3 = *(int *)(iVar2 + 0x40c);
  if (*(int *)(iVar3 + 0x18) != 0) {
    *(undefined4 *)(*(int *)(iVar3 + 0x18) + 0xc) = *(undefined4 *)(iVar1 + 0xc);
    *(undefined4 *)(*(int *)(iVar3 + 0x18) + 0x10) = *(undefined4 *)(iVar1 + 0x10);
    *(undefined4 *)(*(int *)(iVar3 + 0x18) + 0x14) = *(undefined4 *)(iVar1 + 0x14);
    *(float *)(*(int *)(iVar3 + 0x18) + 0x10) =
         *(float *)(*(int *)(iVar3 + 0x18) + 0x10) + FLOAT_803e62d0;
  }
  if (((param_6 != '\0') && (*(int *)(iVar1 + 0xf4) == 0)) && (*(short *)(iVar2 + 0x402) != 0)) {
    if (*(float *)(iVar2 + 1000) != FLOAT_803e62a8) {
      FUN_8003b5e0(200,0,0,(int)*(float *)(iVar2 + 1000));
    }
    FUN_8003b8f4((double)FLOAT_803e62c8,iVar1,(int)uVar4,param_3,param_4,param_5);
    if ((*(ushort *)(iVar2 + 0x400) & 0x60) != 0) {
      FUN_80099d84((double)FLOAT_803e62c8,(double)*(float *)(iVar2 + 1000),iVar1,3,0);
    }
    iVar2 = *(int *)(iVar3 + 0x18);
    if ((iVar2 != 0) && (*(int *)(iVar2 + 0x50) != 0)) {
      FUN_8003842c(iVar1,3,iVar2 + 0xc,iVar2 + 0x10,iVar2 + 0x14,0);
      FUN_8003b8f4((double)FLOAT_803e62c8,*(undefined4 *)(iVar3 + 0x18),(int)uVar4,param_3,param_4,
                   param_5);
    }
  }
  FUN_80286120();
  return;
}

