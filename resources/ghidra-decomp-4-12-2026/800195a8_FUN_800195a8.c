// Function: FUN_800195a8
// Entry: 800195a8
// Size: 660 bytes

ushort * FUN_800195a8(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                     undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                     uint param_9)

{
  bool bVar1;
  int iVar2;
  ushort *puVar3;
  ushort *puVar4;
  undefined4 in_r7;
  undefined4 in_r8;
  undefined4 in_r9;
  undefined4 in_r10;
  double dVar5;
  double dVar6;
  double dVar7;
  
  if (*(int *)(DAT_803dd66c + 0x1c) == 2) {
    puVar3 = *(ushort **)(DAT_803dd66c + 4);
    for (iVar2 = *(int *)(DAT_803dd66c + 0xc); iVar2 != 0; iVar2 = iVar2 + -1) {
      if (*puVar3 == param_9) {
        return puVar3;
      }
      puVar3 = puVar3 + 6;
    }
    iVar2 = 8;
    puVar3 = (ushort *)0x8033a680;
    do {
      puVar4 = puVar3;
      puVar3 = puVar4 + -6;
      bVar1 = iVar2 == 0;
      iVar2 = iVar2 + -1;
      if (bVar1) {
        DAT_803dd5fc = DAT_803dd5fc + 1;
        if (7 < DAT_803dd5fc) {
          DAT_803dd5fc = 0;
        }
        DAT_803dd5f4 = (ushort *)(&DAT_8033a620 + DAT_803dd5fc * 0xc);
        DAT_803dd5f8 = *(int *)(&DAT_8033a628)[DAT_803dd5fc * 3];
        *DAT_803dd5f4 = 0xffff;
        DAT_803dd5f0 = (float *)(&DAT_8033a600 + DAT_803dd5fc * 4);
        FUN_8028fde8(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,DAT_803dd5f8,
                     &DAT_803dc034,param_9,(&PTR_s_Animtest_802c7a1c)[DAT_803dd65c],in_r7,in_r8,
                     in_r9,in_r10);
        *DAT_803dd5f4 = (ushort)param_9;
        *DAT_803dd5f0 = FLOAT_803df384;
        return DAT_803dd5f4;
      }
    } while (*puVar3 != param_9);
    dVar7 = (double)FLOAT_803df384;
    *(float *)(&DAT_8033a5e0 + iVar2 * 4) = FLOAT_803df384;
    dVar6 = (double)FLOAT_803df39c;
    if ((dVar7 < dVar6) &&
       (dVar5 = (double)FLOAT_803dc074,
       *(float *)(&DAT_8033a600 + iVar2 * 4) = (float)(dVar7 + dVar5),
       dVar6 <= (double)(float)(dVar7 + dVar5))) {
      FUN_8028fde8(dVar6,dVar7,param_3,param_4,param_5,param_6,param_7,param_8,
                   **(int **)(puVar4 + -2),s_<_d_s_not_in__s>_802ca9c0,param_9,
                   (&PTR_s_Animtest_802c7a1c)[DAT_803dd65c],in_r7,in_r8,in_r9,in_r10);
    }
  }
  else {
    DAT_803dd5fc = DAT_803dd5fc + 1;
    if (7 < DAT_803dd5fc) {
      DAT_803dd5fc = 0;
    }
    puVar4 = (ushort *)(&DAT_8033a620 + DAT_803dd5fc * 0xc);
    DAT_803dd5f8 = *(int *)(&DAT_8033a628)[DAT_803dd5fc * 3];
    DAT_803dd5f4 = puVar4;
    *puVar4 = 0xffff;
    DAT_803dd5f0 = (float *)(&DAT_8033a600 + DAT_803dd5fc * 4);
    iVar2 = *(int *)(DAT_803dd66c + 0x1c);
    puVar3 = DAT_803dd5f4;
    if (iVar2 != 2) {
      if (iVar2 < 2) {
        if (iVar2 == 0) {
          FUN_8028fde8(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,DAT_803dd5f8,
                       s_<uninitialised>_802ca988,puVar4,&DAT_802c94c0,in_r7,in_r8,in_r9,in_r10);
          puVar3 = DAT_803dd5f4;
        }
        else if (-1 < iVar2) {
          FUN_8028fde8(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,DAT_803dd5f8,
                       s_<loading>_802ca998,puVar4,&DAT_802c94c0,in_r7,in_r8,in_r9,in_r10);
          puVar3 = DAT_803dd5f4;
        }
      }
      else if (iVar2 == 4) {
        FUN_8028fde8(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,DAT_803dd5f8,
                     s_<no_file_>_802ca9b4,puVar4,&DAT_802c94c0,in_r7,in_r8,in_r9,in_r10);
        puVar3 = DAT_803dd5f4;
      }
      else if (iVar2 < 4) {
        FUN_8028fde8(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,DAT_803dd5f8,
                     s_<file_empty_>_802ca9a4,puVar4,&DAT_802c94c0,in_r7,in_r8,in_r9,in_r10);
        puVar3 = DAT_803dd5f4;
      }
    }
  }
  return puVar3;
}

