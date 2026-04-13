// Function: FUN_8001947c
// Entry: 8001947c
// Size: 300 bytes

undefined2 *
FUN_8001947c(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
            undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,uint param_9
            ,undefined4 param_10,undefined4 param_11,undefined4 param_12,undefined4 param_13,
            undefined4 param_14,undefined4 param_15,undefined4 param_16)

{
  int iVar1;
  ushort *puVar2;
  undefined2 *puVar3;
  
  if (*(int *)(DAT_803dd66c + 0x1c) == 2) {
    puVar2 = FUN_800195a8(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9);
    puVar3 = (undefined2 *)**(undefined4 **)(puVar2 + 4);
  }
  else {
    DAT_803dd5fc = DAT_803dd5fc + 1;
    if (7 < DAT_803dd5fc) {
      DAT_803dd5fc = 0;
    }
    DAT_803dd5f4 = (undefined2 *)(&DAT_8033a620 + DAT_803dd5fc * 0xc);
    DAT_803dd5f8 = *(int *)(&DAT_8033a628)[DAT_803dd5fc * 3];
    *DAT_803dd5f4 = 0xffff;
    DAT_803dd5f0 = &DAT_8033a600 + DAT_803dd5fc * 4;
    iVar1 = *(int *)(DAT_803dd66c + 0x1c);
    puVar3 = DAT_803dd5f4;
    if (iVar1 != 2) {
      if (iVar1 < 2) {
        if (iVar1 == 0) {
          FUN_8028fde8(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,DAT_803dd5f8,
                       s_<uninitialised>_802ca988,&DAT_802c94c0,param_12,param_13,param_14,param_15,
                       param_16);
          puVar3 = DAT_803dd5f4;
        }
        else if (-1 < iVar1) {
          FUN_8028fde8(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,DAT_803dd5f8,
                       s_<loading>_802ca998,&DAT_802c94c0,param_12,param_13,param_14,param_15,
                       param_16);
          puVar3 = DAT_803dd5f4;
        }
      }
      else if (iVar1 == 4) {
        FUN_8028fde8(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,DAT_803dd5f8,
                     s_<no_file_>_802ca9b4,&DAT_802c94c0,param_12,param_13,param_14,param_15,
                     param_16);
        puVar3 = DAT_803dd5f4;
      }
      else if (iVar1 < 4) {
        FUN_8028fde8(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,DAT_803dd5f8,
                     s_<file_empty_>_802ca9a4,&DAT_802c94c0,param_12,param_13,param_14,param_15,
                     param_16);
        puVar3 = DAT_803dd5f4;
      }
    }
  }
  return puVar3;
}

