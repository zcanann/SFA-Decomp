// Function: FUN_80210bd0
// Entry: 80210bd0
// Size: 352 bytes

void FUN_80210bd0(int param_1,int param_2)

{
  short sVar1;
  int iVar2;
  undefined4 *puVar3;
  
  *(code **)(param_1 + 0xbc) = FUN_8020fd58;
  iVar2 = *(int *)(param_1 + 100);
  if (iVar2 != 0) {
    *(uint *)(iVar2 + 0x30) = *(uint *)(iVar2 + 0x30) | 0x4000;
    *(undefined *)(*(int *)(param_1 + 100) + 0x3a) = 100;
    *(undefined *)(*(int *)(param_1 + 100) + 0x3b) = 0x96;
  }
  puVar3 = *(undefined4 **)(param_1 + 0xb8);
  *puVar3 = 0;
  *(undefined *)((int)puVar3 + 0xa2) = *(undefined *)(param_2 + 0x27);
  *(undefined *)(puVar3 + 0x29) = 4;
  *(undefined *)((int)puVar3 + 0xa5) = 0xff;
  sVar1 = *(short *)(param_1 + 0x46);
  if (sVar1 < 0x38b) {
    if ((sVar1 == 0x170) || ((sVar1 < 0x170 || (sVar1 < 0x389)))) {
LAB_80210c90:
      puVar3[1] = &DAT_8032afc0;
      *(undefined2 *)(puVar3 + 0x2a) = 0x100;
      goto LAB_80210cc4;
    }
LAB_80210ca4:
    puVar3[1] = &DAT_8032afbc;
    *(undefined2 *)(puVar3 + 0x2a) = 0x400;
  }
  else {
    if (sVar1 == 0x4d3) goto LAB_80210ca4;
    if ((0x4d2 < sVar1) || (sVar1 != 1000)) goto LAB_80210c90;
  }
  puVar3[1] = &DAT_8032afc4;
  *(undefined2 *)(puVar3 + 0x2a) = 0x400;
LAB_80210cc4:
  *(undefined *)((int)puVar3 + 0xa6) = 0;
  puVar3[0x27] = 100;
  puVar3[0xc] = FLOAT_803e7384;
  FUN_800803f8(puVar3 + 0x26);
  FUN_80080404((float *)(puVar3 + 0x26),(short)DAT_8032afa4);
  FUN_80080304(-0x7fcd5098,6);
  DAT_803de9b8 = 0x96;
  *(byte *)((int)puVar3 + 0xaa) = *(byte *)((int)puVar3 + 0xaa) & 0x7f;
  return;
}

