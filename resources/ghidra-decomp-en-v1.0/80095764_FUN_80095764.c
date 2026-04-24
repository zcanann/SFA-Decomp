// Function: FUN_80095764
// Entry: 80095764
// Size: 400 bytes

void FUN_80095764(double param_1,double param_2,double param_3,double param_4,undefined2 param_5,
                 uint param_6)

{
  int iVar1;
  undefined2 *puVar2;
  int iVar3;
  
  iVar3 = 0;
  for (iVar1 = DAT_803dd238; (iVar3 < 0x1e && (*(short *)(iVar1 + 0x16) != 0)); iVar1 = iVar1 + 0x1c
      ) {
    iVar3 = iVar3 + 1;
  }
  if (iVar3 < 0x1e) {
    iVar1 = iVar3 * 4;
    puVar2 = (undefined2 *)(DAT_803dd24c + iVar3 * 0x40);
    *puVar2 = 0xfed4;
    puVar2[1] = 0;
    puVar2[2] = 300;
    *(undefined *)((int)puVar2 + 0xf) = 0xff;
    puVar2[4] = 0;
    puVar2[5] = 0;
    puVar2 = (undefined2 *)(DAT_803dd24c + (iVar1 + 1) * 0x10);
    *puVar2 = 0xfed4;
    puVar2[1] = 0;
    puVar2[2] = 0xfed4;
    *(undefined *)((int)puVar2 + 0xf) = 0xff;
    puVar2[4] = 0;
    puVar2[5] = 0x7f;
    puVar2 = (undefined2 *)(DAT_803dd24c + (iVar1 + 2) * 0x10);
    *puVar2 = 300;
    puVar2[1] = 0;
    puVar2[2] = 0xfed4;
    *(undefined *)((int)puVar2 + 0xf) = 0xff;
    puVar2[4] = 0x7f;
    puVar2[5] = 0x7f;
    puVar2 = (undefined2 *)(DAT_803dd24c + (iVar1 + 3) * 0x10);
    *puVar2 = 300;
    puVar2[1] = 0;
    puVar2[2] = 300;
    *(undefined *)((int)puVar2 + 0xf) = 0xff;
    puVar2[4] = 0x7f;
    puVar2[5] = 0;
    iVar3 = iVar3 * 0x1c;
    *(float *)(DAT_803dd238 + iVar3 + 0xc) = (float)param_4;
    *(undefined2 *)(DAT_803dd238 + iVar3 + 0x16) = 0xff;
    *(float *)(DAT_803dd238 + iVar3) = (float)param_1;
    *(float *)(DAT_803dd238 + iVar3 + 4) = (float)param_2;
    *(float *)(DAT_803dd238 + iVar3 + 8) = (float)param_3;
    *(undefined2 *)(DAT_803dd238 + iVar3 + 0x14) = param_5;
    *(float *)(DAT_803dd238 + iVar3 + 0x10) = FLOAT_803dd20c;
    *(short *)(DAT_803dd238 + iVar3 + 0x18) =
         (short)(int)(FLOAT_803df2e8 *
                     (float)((double)CONCAT44(0x43300000,param_6 ^ 0x80000000) - DOUBLE_803df308));
    DAT_803dd23c = DAT_803dd23c + 1;
  }
  return;
}

