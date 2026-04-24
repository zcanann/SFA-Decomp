// Function: FUN_800393e8
// Entry: 800393e8
// Size: 264 bytes

void FUN_800393e8(undefined4 param_1,undefined4 param_2,ushort *param_3,uint param_4)

{
  ushort uVar1;
  ushort uVar2;
  uint uVar3;
  bool bVar5;
  int *piVar4;
  undefined *puVar6;
  undefined8 uVar7;
  
  uVar7 = FUN_80286840();
  uVar3 = (uint)((ulonglong)uVar7 >> 0x20);
  puVar6 = (undefined *)uVar7;
  uVar1 = param_3[1];
  uVar2 = *param_3;
  if (((param_4 & 0xff) != 0) || (bVar5 = FUN_8000b598(uVar3,0x10), !bVar5)) {
    FUN_8000bad0(uVar3,0x10,uVar2);
    *(float *)(puVar6 + 0xc) = FLOAT_803df648;
    *(ushort *)(puVar6 + 0x14) = -uVar1;
    *puVar6 = 1;
    *(float *)(puVar6 + 4) = FLOAT_803df61c;
  }
  if ((*(byte *)(param_3 + 2) != 0) &&
     (piVar4 = *(int **)(*(int *)(uVar3 + 0x7c) + *(char *)(uVar3 + 0xad) * 4),
     *(char *)(*piVar4 + 0xf9) != '\0')) {
    FUN_80027a90((double)(FLOAT_803df61c / FLOAT_803dc0c4),piVar4,2,
                 (int)*(char *)(piVar4[10] + 0x2d),*(byte *)(param_3 + 2) - 1,0);
    param_3[1] = 0;
  }
  FUN_8028688c();
  return;
}

