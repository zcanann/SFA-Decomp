// Function: FUN_802b8864
// Entry: 802b8864
// Size: 500 bytes

/* WARNING: Removing unreachable block (ram,0x802b8a38) */

void FUN_802b8864(undefined4 param_1,undefined4 param_2,int param_3)

{
  float fVar1;
  int iVar2;
  int iVar3;
  char cVar4;
  byte bVar5;
  int iVar6;
  undefined4 uVar7;
  int iVar8;
  undefined4 uVar9;
  undefined8 in_f31;
  double dVar10;
  float local_58;
  float local_54;
  float local_50;
  undefined auStack76 [12];
  float local_40;
  float local_3c;
  float local_38;
  undefined auStack8 [8];
  
  uVar9 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  iVar2 = FUN_802860d8();
  fVar1 = FLOAT_803e8180;
  iVar8 = *(int *)(iVar2 + 0xb8);
  iVar6 = *(int *)(iVar2 + 0x4c);
  iVar3 = *(int *)(iVar8 + 0x40c);
  if ((*(float *)(iVar3 + 0x10) != FLOAT_803e8180) &&
     (*(float *)(iVar3 + 0x10) = *(float *)(iVar3 + 0x10) - FLOAT_803db414,
     *(float *)(iVar3 + 0x10) <= fVar1)) {
    FUN_8002cbc4();
  }
  for (bVar5 = 0; bVar5 < *(byte *)(param_3 + 0x8b); bVar5 = bVar5 + 1) {
    if (*(char *)(param_3 + bVar5 + 0x81) == '\x01') {
      *(byte *)(iVar8 + 0x404) = *(byte *)(iVar8 + 0x404) | 1;
      FUN_800200e8((int)*(short *)(iVar6 + 0x1c),1);
      local_40 = FLOAT_803e8180;
      local_3c = FLOAT_803e81c4;
      local_38 = FLOAT_803e8180;
      dVar10 = (double)FLOAT_803e8210;
      for (cVar4 = '\x19'; cVar4 != '\0'; cVar4 = cVar4 + -1) {
        FUN_80098b18((double)(float)(dVar10 * (double)*(float *)(iVar2 + 8)),iVar2,3,0,0,auStack76);
      }
    }
  }
  if (((*(short *)(iVar6 + 0x1a) == 0x64c) &&
      (FUN_802b86b8(iVar2,iVar8,iVar8), (*(byte *)(iVar8 + 0x404) & 1) != 0)) &&
     ((*(ushort *)(iVar2 + 0xb0) & 0x800) != 0)) {
    iVar3 = *(int *)(iVar8 + 0x40c);
    *(float *)(iVar3 + 0xc) = *(float *)(iVar3 + 0xc) - FLOAT_803db414;
    if (FLOAT_803e8180 < *(float *)(iVar3 + 0xc)) {
      uVar7 = 0;
    }
    else {
      uVar7 = 3;
      *(float *)(iVar3 + 0xc) = *(float *)(iVar3 + 0xc) + FLOAT_803e81c0;
    }
    local_58 = FLOAT_803e8180;
    local_54 = FLOAT_803e81c4;
    local_50 = FLOAT_803e8180;
    FUN_8000da58(iVar2,0x455);
    FUN_80098b18((double)(FLOAT_803e81c8 * *(float *)(iVar2 + 8)),iVar2,3,uVar7,0,&local_58);
  }
  *(ushort *)(iVar8 + 0x400) = *(ushort *)(iVar8 + 0x400) | 2;
  __psq_l0(auStack8,uVar9);
  __psq_l1(auStack8,uVar9);
  FUN_80286124(0);
  return;
}

