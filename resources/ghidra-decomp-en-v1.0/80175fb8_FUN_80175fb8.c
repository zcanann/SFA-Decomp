// Function: FUN_80175fb8
// Entry: 80175fb8
// Size: 300 bytes

void FUN_80175fb8(undefined4 param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4,
                 undefined4 param_5,char param_6)

{
  short sVar1;
  float fVar2;
  int iVar3;
  int iVar4;
  undefined8 uVar5;
  
  uVar5 = FUN_802860dc();
  fVar2 = FLOAT_803e3528;
  iVar3 = (int)((ulonglong)uVar5 >> 0x20);
  if (param_6 == '\0') goto LAB_801760cc;
  iVar4 = *(int *)(iVar3 + 0xb8);
  sVar1 = *(short *)(iVar3 + 0x46);
  if (sVar1 == 0x411) {
    iVar4 = FUN_8001ffb4((int)*(short *)(iVar4 + 0xac));
joined_r0x80176038:
    if (iVar4 != 0) goto LAB_801760cc;
  }
  else if (sVar1 < 0x411) {
    if (sVar1 == 0x21e) {
      iVar4 = FUN_8001ffb4((int)*(short *)(iVar4 + 0xac));
      goto joined_r0x80176038;
    }
  }
  else if ((sVar1 == 0x54a) && (FLOAT_803e3528 < *(float *)(iVar4 + 0x14))) {
    *(float *)(iVar4 + 0x14) = *(float *)(iVar4 + 0x14) - FLOAT_803db414;
    if (fVar2 < *(float *)(iVar4 + 0x14)) {
      FUN_8003b5e0(200,0,0,0xff);
    }
    else {
      *(float *)(iVar4 + 0x14) = fVar2;
    }
  }
  iVar4 = **(int **)(*(int *)(iVar3 + 0x7c) + *(char *)(iVar3 + 0xad) * 4);
  *(ushort *)(iVar4 + 2) = *(ushort *)(iVar4 + 2) | 2;
  FUN_8003b8f4((double)FLOAT_803e3588,iVar3,(int)uVar5,param_3,param_4,param_5);
LAB_801760cc:
  FUN_80286128();
  return;
}

