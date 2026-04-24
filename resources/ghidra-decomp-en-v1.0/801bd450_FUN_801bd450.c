// Function: FUN_801bd450
// Entry: 801bd450
// Size: 860 bytes

void FUN_801bd450(int param_1)

{
  uint uVar1;
  undefined4 uVar2;
  int iVar3;
  int iVar4;
  int iVar5;
  
  iVar4 = *(int *)(param_1 + 0xb8);
  iVar3 = *(int *)(param_1 + 0x4c);
  FUN_8002b9ec();
  iVar5 = *(int *)(iVar4 + 0x40c);
  if (*(int *)(param_1 + 0xf4) == 0) {
    if (FLOAT_803e4bd8 < *(float *)(iVar5 + 0xac)) {
      FUN_80016870(0x432);
      *(float *)(iVar5 + 0xac) = *(float *)(iVar5 + 0xac) - FLOAT_803db414;
      if (*(float *)(iVar5 + 0xac) < FLOAT_803e4bd8) {
        *(float *)(iVar5 + 0xac) = FLOAT_803e4bd8;
      }
    }
    FUN_8003393c(param_1);
    if (*(int *)(param_1 + 0xf8) == 0) {
      *(undefined4 *)(param_1 + 0xc) = *(undefined4 *)(iVar3 + 8);
      *(undefined4 *)(param_1 + 0x10) = *(undefined4 *)(iVar3 + 0xc);
      *(undefined4 *)(param_1 + 0x14) = *(undefined4 *)(iVar3 + 0x10);
      (**(code **)(*DAT_803dca54 + 0x48))((int)*(char *)(iVar3 + 0x2e),param_1,0xffffffff);
      *(undefined4 *)(param_1 + 0xf8) = 1;
    }
    else {
      if ((*(ushort *)(iVar4 + 0x400) & 2) != 0) {
        (**(code **)(*DAT_803dcab8 + 0x28))
                  (param_1,iVar4,iVar4 + 0x35c,(int)*(short *)(iVar4 + 0x3f4),iVar4 + 0x405,0,0,0,1)
        ;
        *(ushort *)(iVar4 + 0x400) = *(ushort *)(iVar4 + 0x400) & 0xfffd;
        *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) & 0xf7;
        *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) | 0x80;
        uVar1 = FUN_8001ffb4(0x20c);
        if (uVar1 < 3) {
          *(undefined2 *)(iVar4 + 0x402) = 1;
          *(undefined *)(iVar4 + 0x354) = 3;
          *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) & 0xf7;
          *(float *)(iVar5 + 0xa4) = FLOAT_803e4c44;
          FUN_800200e8(0x9e,1);
        }
        else {
          *(undefined2 *)(iVar4 + 0x402) = 2;
          *(undefined *)(iVar4 + 0x354) = 3;
          *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) & 0xf7;
          FUN_800200e8(0x9e,0);
        }
      }
      if ((*(short *)(iVar4 + 0x402) == 0) || (*(short *)(iVar4 + 0x402) == 3)) {
        if ((*(char *)(iVar5 + 0xb4) != '\0') &&
           (*(char *)(iVar5 + 0xb4) = *(char *)(iVar5 + 0xb4) + -1, *(char *)(iVar5 + 0xb4) == '\0')
           ) {
          FUN_8002b47c(param_1,&DAT_803ac9ac,0);
          uVar2 = FUN_8002b588(param_1);
          FUN_80028488((double)(*(float *)(param_1 + 0xa8) * *(float *)(param_1 + 8)),param_1,uVar2,
                       &DAT_803ac9ac,1);
        }
        if (*(char *)(iVar5 + 0xb6) < '\0') {
          FUN_80008cbc(0,0,0xdb,0);
          FUN_80008cbc(0,0,0xdc,0);
          FUN_80089710(7,1,0);
          FUN_800894a8((double)FLOAT_803e4c4c,(double)FLOAT_803e4c50,(double)FLOAT_803e4c54,7);
          FUN_800895e0(7,0xa0,0xa0,0xff,0x7f,0x28);
          *(byte *)(iVar5 + 0xb6) = *(byte *)(iVar5 + 0xb6) & 0x7f;
        }
      }
      else {
        if ((*(ushort *)(iVar4 + 0x400) & 4) == 0) {
          uVar2 = FUN_8002b9ec();
          *(undefined4 *)(iVar4 + 0x2d0) = uVar2;
        }
        else {
          uVar2 = FUN_8002b9ac();
          *(undefined4 *)(iVar4 + 0x2d0) = uVar2;
        }
        if (*(int *)(param_1 + 200) != 0) {
          *(undefined4 *)(*(int *)(param_1 + 200) + 0x30) = *(undefined4 *)(param_1 + 0x30);
        }
        FUN_801bc7e4(param_1,0,iVar4,iVar4);
        FUN_8011508c(&DAT_803ac9dc,*(undefined4 *)(iVar4 + 0x2d0));
        FUN_80115094(param_1,&DAT_803ac9dc);
        FUN_801bbb44(param_1,iVar4);
      }
    }
  }
  return;
}

