// Function: FUN_802c11cc
// Entry: 802c11cc
// Size: 296 bytes

undefined4 FUN_802c11cc(undefined2 *param_1,uint *param_2)

{
  float fVar1;
  undefined4 uVar2;
  int iVar3;
  uint uVar4;
  int iVar5;
  int iVar6;
  
  iVar5 = *(int *)(param_1 + 0x26);
  *param_2 = *param_2 | 0x200000;
  if (*(char *)((int)param_2 + 0x27a) == '\0') {
    iVar6 = *(int *)(param_1 + 0x5c);
    iVar3 = FUN_8002bac4();
    FUN_800217c8((float *)(param_1 + 0xc),(float *)(iVar3 + 0x18));
    uVar4 = FUN_80022150((double)FLOAT_803e9090,(double)FLOAT_803e90a4,(float *)(iVar6 + 0xb54));
    if (uVar4 != 0) {
      FUN_8000bb38((uint)param_1,0x464);
    }
    uVar4 = FUN_80020078((int)*(short *)(iVar5 + 0x1e));
    if (uVar4 == 0) {
      uVar2 = 0;
    }
    else {
      *(undefined4 *)(param_1 + 0x7a) = 0;
      FUN_80036018((int)param_1);
      FUN_80035f9c((int)param_1);
      *(byte *)(iVar6 + 0xbc0) =
           (byte)(((uint)(-(int)*(short *)(iVar6 + 0xbb0) & ~(int)*(short *)(iVar6 + 0xbb0)) >> 0x1f
                  ) << 4) | *(byte *)(iVar6 + 0xbc0) & 0xef;
      *param_1 = DAT_803dd402;
      uVar2 = 3;
    }
  }
  else {
    FUN_80035ff8((int)param_1);
    *(undefined *)((int)param_2 + 0x25f) = 0;
    param_2[0xa8] = (uint)FLOAT_803e90a0;
    fVar1 = FLOAT_803e903c;
    param_2[0xa5] = (uint)FLOAT_803e903c;
    param_2[0xa1] = (uint)fVar1;
    param_2[0xa0] = (uint)fVar1;
    *(float *)(param_1 + 0x12) = fVar1;
    *(float *)(param_1 + 0x14) = fVar1;
    *(float *)(param_1 + 0x16) = fVar1;
    uVar2 = 0;
  }
  return uVar2;
}

