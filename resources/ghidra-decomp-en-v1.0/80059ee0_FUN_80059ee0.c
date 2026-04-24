// Function: FUN_80059ee0
// Entry: 80059ee0
// Size: 556 bytes

void FUN_80059ee0(void)

{
  float fVar1;
  int iVar2;
  int iVar3;
  int iVar4;
  int iVar5;
  undefined8 uVar6;
  int local_28;
  undefined auStack36 [4];
  int local_20 [8];
  
  uVar6 = FUN_802860dc();
  iVar2 = (int)((ulonglong)uVar6 >> 0x20);
  iVar3 = iVar2 * 0x1c;
  iVar5 = *(int *)(DAT_803dce7c + iVar3);
  iVar4 = *(int *)(DAT_803dce7c + iVar3 + 0x1c) - iVar5;
  FUN_80048ba4(iVar5,local_20,auStack36,&local_28);
  DAT_803dcea0 = FUN_80023cc8(iVar4 + (local_20[0] + 7 >> 3) + 0x401 + local_28,5,0);
  FUN_80048f48(0x1d,DAT_803dcea0,iVar5,iVar4);
  *(int *)(DAT_803dcea0 + 0xc) = (DAT_803dcea0 + *(int *)(DAT_803dce7c + iVar3 + 4)) - iVar5;
  *(int *)(DAT_803dcea0 + 0x14) = (DAT_803dcea0 + *(int *)(DAT_803dce7c + iVar3 + 8)) - iVar5;
  *(int *)(DAT_803dcea0 + 0x30) = (DAT_803dcea0 + *(int *)(DAT_803dce7c + iVar3 + 0xc)) - iVar5;
  *(int *)(DAT_803dcea0 + 0x2c) = (DAT_803dcea0 + *(int *)(DAT_803dce7c + iVar3 + 0x10)) - iVar5;
  *(int *)(DAT_803dcea0 + 0x34) = (DAT_803dcea0 + *(int *)(DAT_803dce7c + iVar3 + 0x14)) - iVar5;
  *(int *)(DAT_803dcea0 + 0x20) = (DAT_803dcea0 + *(int *)(DAT_803dce7c + iVar3 + 0x18)) - iVar5;
  FUN_80048328(*(undefined4 *)(DAT_803dce7c + iVar3 + 0x18),iVar2,
               *(undefined4 *)(DAT_803dcea0 + 0x20));
  *(int *)(DAT_803dcea0 + 0x10) =
       (local_28 + *(int *)(DAT_803dce7c + iVar3 + 0x1c) + DAT_803dcea0) - iVar5;
  for (iVar3 = 0; fVar1 = FLOAT_803debcc, iVar3 < (local_20[0] + 7 >> 3) + 1; iVar3 = iVar3 + 1) {
    *(undefined *)(*(int *)(DAT_803dcea0 + 0x10) + iVar3) = 0;
  }
  *(float *)(DAT_803dcea0 + 0x24) = FLOAT_803debcc;
  *(float *)(DAT_803dcea0 + 0x28) = fVar1;
  *(undefined *)(DAT_803dcea0 + 0x18) = 0;
  *(undefined *)(DAT_803dcea0 + 0x19) = 0;
  if ((int)uVar6 == 0) {
    FUN_8005972c(DAT_803dcea0,iVar2 * 0x8c + -0x7fc7dd38,iVar2,0);
    (**(code **)(*DAT_803dcaac + 0x58))(iVar2);
  }
  FUN_80286128(DAT_803dcea0);
  return;
}

