// Function: FUN_802c0a5c
// Entry: 802c0a5c
// Size: 296 bytes

undefined4 FUN_802c0a5c(undefined2 *param_1,uint *param_2)

{
  float fVar1;
  undefined4 uVar2;
  int iVar3;
  int iVar4;
  int iVar5;
  
  iVar4 = *(int *)(param_1 + 0x26);
  *param_2 = *param_2 | 0x200000;
  if (*(char *)((int)param_2 + 0x27a) == '\0') {
    iVar5 = *(int *)(param_1 + 0x5c);
    iVar3 = FUN_8002b9ec();
    FUN_80021704(param_1 + 0xc,iVar3 + 0x18);
    iVar3 = FUN_8002208c((double)FLOAT_803e83f8,(double)FLOAT_803e840c,iVar5 + 0xb54);
    if (iVar3 != 0) {
      FUN_8000bb18(param_1,0x464);
    }
    iVar4 = FUN_8001ffb4((int)*(short *)(iVar4 + 0x1e));
    if (iVar4 == 0) {
      uVar2 = 0;
    }
    else {
      *(undefined4 *)(param_1 + 0x7a) = 0;
      FUN_80035f20(param_1);
      FUN_80035ea4(param_1);
      *(byte *)(iVar5 + 0xbc0) =
           (byte)(((uint)(-(int)*(short *)(iVar5 + 0xbb0) & ~(int)*(short *)(iVar5 + 0xbb0)) >> 0x1f
                  ) << 4) | *(byte *)(iVar5 + 0xbc0) & 0xef;
      *param_1 = DAT_803dc79a;
      uVar2 = 3;
    }
  }
  else {
    FUN_80035f00();
    *(undefined *)((int)param_2 + 0x25f) = 0;
    param_2[0xa8] = (uint)FLOAT_803e8408;
    fVar1 = FLOAT_803e83a4;
    param_2[0xa5] = (uint)FLOAT_803e83a4;
    param_2[0xa1] = (uint)fVar1;
    param_2[0xa0] = (uint)fVar1;
    *(float *)(param_1 + 0x12) = fVar1;
    *(float *)(param_1 + 0x14) = fVar1;
    *(float *)(param_1 + 0x16) = fVar1;
    uVar2 = 0;
  }
  return uVar2;
}

