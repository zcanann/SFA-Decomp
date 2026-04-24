// Function: FUN_8015d7b0
// Entry: 8015d7b0
// Size: 504 bytes

void FUN_8015d7b0(int param_1)

{
  int iVar1;
  int iVar2;
  int iVar3;
  
  iVar3 = *(int *)(param_1 + 0xb8);
  iVar2 = *(int *)(param_1 + 0x4c);
  if (*(int *)(param_1 + 0xf4) == 0) {
    if (*(int *)(param_1 + 0xf8) == 0) {
      *(undefined4 *)(param_1 + 0xc) = *(undefined4 *)(iVar2 + 8);
      *(undefined4 *)(param_1 + 0x10) = *(undefined4 *)(iVar2 + 0xc);
      *(undefined4 *)(param_1 + 0x14) = *(undefined4 *)(iVar2 + 0x10);
      (**(code **)(*DAT_803dca54 + 0x48))((int)*(char *)(iVar2 + 0x2e),param_1,0xffffffff);
      *(undefined4 *)(param_1 + 0xf8) = 1;
    }
    else {
      iVar1 = (**(code **)(*DAT_803dcab8 + 0x30))(param_1,iVar3,0);
      if (iVar1 == 0) {
        *(undefined2 *)(iVar3 + 0x402) = 0;
      }
      else {
        FUN_8015d3c0(param_1,iVar3,iVar3);
        FUN_8015cbd0(param_1,iVar3);
        if (*(short *)(iVar3 + 0x402) == 0) {
          FUN_8015d098(param_1,iVar3,iVar3);
        }
        else {
          FUN_8015d27c(param_1,iVar3,iVar3);
        }
        if ((*(byte *)(iVar3 + 0x404) & 2) != 0) {
          *(float *)(param_1 + 0x10) = *(float *)(iVar2 + 0xc) - FLOAT_803e2d90;
        }
      }
    }
  }
  else if (((*(short *)(iVar3 + 0x270) != 3) || ((*(byte *)(iVar3 + 0x404) & 1) != 0)) &&
          (iVar1 = (**(code **)(*DAT_803dcaac + 0x68))(*(undefined4 *)(iVar2 + 0x14)), iVar1 != 0))
  {
    (**(code **)(*DAT_803dcab8 + 0x58))((double)FLOAT_803e2db8,param_1,iVar2,iVar3,0xe,8,0x102,0x26)
    ;
    *(undefined2 *)(iVar3 + 0x402) = 0;
    FUN_8000bb18(param_1,0x263);
    FUN_80030334((double)FLOAT_803e2d14,param_1,8,0x10);
    *(undefined *)(iVar3 + 0x346) = 0;
    *(undefined *)(param_1 + 0x36) = 0xff;
    *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) | 8;
  }
  return;
}

