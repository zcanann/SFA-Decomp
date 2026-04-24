// Function: FUN_801bc7e4
// Entry: 801bc7e4
// Size: 848 bytes

void FUN_801bc7e4(undefined4 param_1,undefined4 param_2,int param_3,int param_4)

{
  float fVar1;
  float fVar2;
  int iVar3;
  int iVar4;
  int iVar5;
  
  iVar3 = FUN_802860dc();
  iVar5 = *(int *)(param_3 + 0x40c);
  iVar4 = FUN_8002b9ac();
  FUN_80035f20(iVar3);
  *(undefined *)(param_4 + 0x25f) = 1;
  (**(code **)(*DAT_803dcab8 + 0x2c))((double)FLOAT_803e4c70,iVar3,param_4,1);
  (**(code **)(*DAT_803dcab8 + 0x54))
            (iVar3,param_4,param_3 + 0x35c,(int)*(short *)(param_3 + 0x3f4),param_3 + 0x405,0,0,0);
  if (*(short *)(param_4 + 0x274) == 6) {
    *(float *)(iVar5 + 0xa0) =
         -(FLOAT_803db414 * (FLOAT_803e4bc8 * *(float *)(iVar3 + 0x98) + FLOAT_803e4c44) -
          *(float *)(iVar5 + 0xa0));
  }
  else {
    *(float *)(iVar5 + 0xa0) = *(float *)(iVar5 + 0xa0) - FLOAT_803db414;
  }
  if (*(float *)(iVar5 + 0xa0) <= FLOAT_803e4bd8) {
    FUN_800200e8(*(undefined2 *)(&DAT_803259e4 + (uint)*(byte *)(iVar5 + 0xb5) * 8),1);
    *(undefined4 *)(iVar5 + 0xa0) =
         *(undefined4 *)(&DAT_803259e0 + (uint)*(byte *)(iVar5 + 0xb5) * 8);
    *(char *)(iVar5 + 0xb5) = *(char *)(iVar5 + 0xb5) + '\x01';
    if (0x17 < *(byte *)(iVar5 + 0xb5)) {
      *(undefined *)(iVar5 + 0xb5) = 0;
    }
  }
  fVar2 = FLOAT_803e4c74;
  if (iVar4 != 0) {
    fVar1 = *(float *)(iVar5 + 0xa4);
    if (((FLOAT_803e4bd8 < fVar1) && (fVar1 <= FLOAT_803e4c74)) &&
       (*(float *)(iVar5 + 0xa4) = fVar1 + FLOAT_803db414, fVar2 <= *(float *)(iVar5 + 0xa4))) {
      (**(code **)(**(int **)(iVar4 + 0x68) + 0x34))(iVar4,1,iVar3);
    }
    fVar2 = FLOAT_803e4bd8;
    if (*(float *)(iVar5 + 0xa8) <= FLOAT_803e4bd8) {
      if (*(short *)(param_3 + 0x402) == 1) {
        *(ushort *)(param_3 + 0x400) = *(ushort *)(param_3 + 0x400) | 4;
        *(float *)(iVar5 + 0xa8) = FLOAT_803e4c44;
        FUN_801bb3e8(iVar3,0);
      }
    }
    else {
      *(float *)(iVar5 + 0xa8) = *(float *)(iVar5 + 0xa8) + FLOAT_803db414;
      if (FLOAT_803e4bec <= *(float *)(iVar5 + 0xa8)) {
        *(ushort *)(param_3 + 0x400) = *(ushort *)(param_3 + 0x400) & 0xfffb;
        *(float *)(iVar5 + 0xa8) = fVar2;
        (**(code **)(**(int **)(iVar4 + 0x68) + 0x34))(iVar4,0,0);
        *(float *)(iVar5 + 0xa4) = FLOAT_803e4c44;
      }
    }
  }
  if (*(short *)(param_3 + 0x402) == 2) {
    FUN_801bb3e8(iVar3,1);
  }
  if ((DAT_803ddb80 & 0x20000) != 0) {
    DAT_803ddb80 = DAT_803ddb80 & 0xfffdffff;
    FUN_801bb328(*(int *)(param_3 + 0x40c) + 4,*(int *)(param_3 + 0x40c) + 0x94);
  }
  if ((*(ushort *)(param_3 + 0x400) & 4) != 0) {
    DAT_803ddb80 = DAT_803ddb80 | 8;
  }
  if (*(short *)(param_3 + 0x402) == 1) {
    (**(code **)(**(int **)(iVar4 + 0x68) + 0x28))(iVar4,iVar3,1,2);
    *(undefined *)(iVar3 + 0xe4) = 1;
  }
  else {
    *(undefined *)(iVar3 + 0xe4) = 2;
  }
  *(undefined4 *)(param_3 + 0x3e0) = *(undefined4 *)(iVar3 + 0xc0);
  *(undefined4 *)(iVar3 + 0xc0) = 0;
  (**(code **)(*DAT_803dca8c + 8))
            ((double)FLOAT_803db414,(double)FLOAT_803db414,iVar3,param_4,&DAT_803ad018,&DAT_803ad000
            );
  *(undefined4 *)(iVar3 + 0xc0) = *(undefined4 *)(param_3 + 0x3e0);
  FUN_80286128();
  return;
}

