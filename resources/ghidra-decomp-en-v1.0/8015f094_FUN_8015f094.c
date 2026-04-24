// Function: FUN_8015f094
// Entry: 8015f094
// Size: 836 bytes

void FUN_8015f094(void)

{
  int iVar1;
  int iVar2;
  int iVar3;
  int iVar4;
  int iVar5;
  undefined auStack40 [40];
  
  iVar1 = FUN_802860dc();
  iVar5 = *(int *)(iVar1 + 0xb8);
  iVar4 = *(int *)(iVar1 + 0x4c);
  if (*(int *)(iVar1 + 0xf4) == 0) {
    if (*(int *)(iVar1 + 0xf8) == 0) {
      *(undefined4 *)(iVar1 + 0xc) = *(undefined4 *)(iVar4 + 8);
      *(undefined4 *)(iVar1 + 0x10) = *(undefined4 *)(iVar4 + 0xc);
      *(undefined4 *)(iVar1 + 0x14) = *(undefined4 *)(iVar4 + 0x10);
      (**(code **)(*DAT_803dca54 + 0x48))((int)*(char *)(iVar4 + 0x2e),iVar1,0xffffffff);
      *(undefined4 *)(iVar1 + 0xf8) = 1;
    }
    else {
      iVar2 = (**(code **)(*DAT_803dcab8 + 0x30))(iVar1,iVar5,0);
      if (iVar2 == 0) {
        *(undefined2 *)(iVar5 + 0x402) = 0;
      }
      else if (((*(byte *)(iVar5 + 0x404) & 0x10) == 0) ||
              (iVar2 = (**(code **)(*DAT_803dca58 + 0x24))(auStack40), iVar2 != 0)) {
        FUN_8015ed1c(iVar1,iVar5,iVar5);
        if (*(short *)(iVar5 + 0x402) == 0) {
          FUN_8015eb6c(iVar1,iVar5,iVar5);
        }
        else {
          iVar2 = *(int *)(iVar5 + 0x40c);
          if ((*(byte *)(iVar2 + 8) & 1) != 0) {
            FUN_8015ea48(iVar1,iVar5);
          }
          if ((*(byte *)(iVar2 + 8) & 2) != 0) {
            (**(code **)(*DAT_803dca88 + 8))(iVar1,0x345,0,1,0xffffffff,0);
          }
          if ((*(byte *)(iVar2 + 8) & 4) != 0) {
            iVar3 = 0;
            do {
              (**(code **)(*DAT_803dca88 + 8))(iVar1,0x343,0,1,0xffffffff,0);
              iVar3 = iVar3 + 1;
            } while (iVar3 < 10);
          }
          *(undefined *)(iVar2 + 8) = 0;
          (**(code **)(*DAT_803dcab8 + 0x2c))((double)FLOAT_803e2dc8,iVar1,iVar5,0xffffffff);
          (**(code **)(*DAT_803dca8c + 0x30))((double)FLOAT_803db414,iVar1,iVar5,4);
          *(undefined4 *)(iVar5 + 0x3e0) = *(undefined4 *)(iVar1 + 0xc0);
          *(undefined4 *)(iVar1 + 0xc0) = 0;
          (**(code **)(*DAT_803dca8c + 8))
                    ((double)FLOAT_803db414,(double)FLOAT_803db414,iVar1,iVar5,&DAT_803ac5b0,
                     &DAT_803ac598);
          *(undefined4 *)(iVar1 + 0xc0) = *(undefined4 *)(iVar5 + 0x3e0);
        }
        *(float *)(iVar1 + 0x10) = *(float *)(iVar4 + 0xc) - FLOAT_803e2e18;
      }
      else {
        *(undefined2 *)(iVar5 + 0x402) = 0;
      }
    }
  }
  else if (((*(short *)(iVar5 + 0x270) != 3) || ((*(byte *)(iVar5 + 0x404) & 1) != 0)) &&
          (iVar2 = (**(code **)(*DAT_803dcaac + 0x68))(*(undefined4 *)(iVar4 + 0x14)), iVar2 != 0))
  {
    (**(code **)(*DAT_803dcab8 + 0x58))((double)FLOAT_803e2e14,iVar1,iVar4,iVar5,7,6,0x102,0x26);
    *(undefined2 *)(iVar5 + 0x402) = 0;
    FUN_8000bb18(iVar1,0x263);
    FUN_80030334((double)FLOAT_803e2dc8,iVar1,8,0x10);
    *(undefined *)(iVar5 + 0x346) = 0;
    *(undefined *)(iVar1 + 0x36) = 0xff;
    *(byte *)(iVar1 + 0xaf) = *(byte *)(iVar1 + 0xaf) | 8;
  }
  FUN_80286128();
  return;
}

