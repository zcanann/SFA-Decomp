// Function: FUN_8021ce3c
// Entry: 8021ce3c
// Size: 284 bytes

void FUN_8021ce3c(undefined2 *param_1,short *param_2)

{
  short sVar1;
  float fVar2;
  int iVar3;
  
  iVar3 = *(int *)(param_1 + 0x5c);
  *param_1 = (short)((int)*(char *)(param_2 + 0xc) << 8);
  *(float *)(iVar3 + 0x118) =
       (float)((double)CONCAT44(0x43300000,(int)param_2[0xd] ^ 0x80000000) - DOUBLE_803e6a60);
  fVar2 = FLOAT_803e6a3c;
  *(float *)(iVar3 + 0x110) = FLOAT_803e6a3c;
  *(byte *)(iVar3 + 0x178) = *(byte *)(iVar3 + 0x178) & 0xdf;
  *(byte *)(iVar3 + 0x178) = *(byte *)(iVar3 + 0x178) & 0xbf | 0x40;
  *(undefined4 *)(iVar3 + 0x170) = 0;
  *(float *)(iVar3 + 0x11c) = fVar2;
  *(float *)(iVar3 + 0x120) = fVar2;
  *(undefined2 *)(iVar3 + 0x176) = 0;
  sVar1 = *param_2;
  if (sVar1 == 0x714) {
    *(byte *)(iVar3 + 0x179) = *(byte *)(iVar3 + 0x179) & 0xef | 0x10;
    *(byte *)(iVar3 + 0x179) = *(byte *)(iVar3 + 0x179) & 0xfb | 4;
    *(byte *)(iVar3 + 0x179) = *(byte *)(iVar3 + 0x179) & 0xf7;
  }
  else if ((sVar1 < 0x714) && (sVar1 == 0x418)) {
    *(byte *)(iVar3 + 0x179) = *(byte *)(iVar3 + 0x179) & 0xef;
    *(byte *)(iVar3 + 0x179) = *(byte *)(iVar3 + 0x179) & 0xfb;
    *(byte *)(iVar3 + 0x179) = *(byte *)(iVar3 + 0x179) & 0xf7 | 8;
  }
  FUN_80037200(param_1,0x46);
  FUN_80037200(param_1,10);
  return;
}

