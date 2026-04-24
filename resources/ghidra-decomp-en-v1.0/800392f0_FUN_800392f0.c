// Function: FUN_800392f0
// Entry: 800392f0
// Size: 264 bytes

void FUN_800392f0(undefined4 param_1,undefined4 param_2,undefined2 *param_3,uint param_4)

{
  short sVar1;
  undefined2 uVar2;
  int iVar3;
  int iVar4;
  int *piVar5;
  undefined *puVar6;
  undefined8 uVar7;
  
  uVar7 = FUN_802860dc();
  iVar3 = (int)((ulonglong)uVar7 >> 0x20);
  puVar6 = (undefined *)uVar7;
  sVar1 = param_3[1];
  uVar2 = *param_3;
  if (((param_4 & 0xff) != 0) || (iVar4 = FUN_8000b578(iVar3,0x10), iVar4 == 0)) {
    FUN_8000bab0(iVar3,0x10,uVar2);
    *(float *)(puVar6 + 0xc) = FLOAT_803de9c8;
    *(short *)(puVar6 + 0x14) = -sVar1;
    *puVar6 = 1;
    *(float *)(puVar6 + 4) = FLOAT_803de99c;
  }
  if ((*(byte *)(param_3 + 2) != 0) &&
     (piVar5 = *(int **)(*(int *)(iVar3 + 0x7c) + *(char *)(iVar3 + 0xad) * 4),
     *(char *)(*piVar5 + 0xf9) != '\0')) {
    FUN_800279cc((double)(FLOAT_803de99c / FLOAT_803db464),piVar5,2,
                 (int)*(char *)(piVar5[10] + 0x2d),*(byte *)(param_3 + 2) - 1,0);
    param_3[1] = 0;
  }
  FUN_80286128();
  return;
}

