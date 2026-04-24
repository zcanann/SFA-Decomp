// Function: FUN_80213da0
// Entry: 80213da0
// Size: 1020 bytes

/* WARNING: Removing unreachable block (ram,0x80213f98) */

void FUN_80213da0(int param_1,int param_2)

{
  float fVar1;
  float fVar2;
  int iVar3;
  undefined4 local_38;
  undefined auStack52 [4];
  int local_30;
  undefined4 local_2c;
  int local_28;
  int local_24;
  undefined4 local_20;
  
  fVar2 = FLOAT_803e67b8;
  local_2c = DAT_802c2550;
  local_28 = DAT_802c2554;
  local_24 = DAT_802c2558;
  local_20 = DAT_802c255c;
  if (DAT_803ddd4c != 0) {
    DAT_803ddd4c = DAT_803ddd4c + -1;
  }
  if (FLOAT_803e67b8 < *(float *)(DAT_803ddd58 + 1000)) {
    *(float *)(DAT_803ddd58 + 1000) =
         FLOAT_803db414 * *(float *)(DAT_803ddd58 + 0x3ec) + *(float *)(DAT_803ddd58 + 1000);
    fVar1 = *(float *)(DAT_803ddd58 + 1000);
    if (fVar2 <= fVar1) {
      if (FLOAT_803e6820 < fVar1) {
        *(float *)(DAT_803ddd58 + 1000) = FLOAT_803e6820 - (fVar1 - FLOAT_803e6820);
        *(float *)(DAT_803ddd58 + 0x3ec) = -*(float *)(DAT_803ddd58 + 0x3ec);
      }
    }
    else {
      *(float *)(DAT_803ddd58 + 1000) = fVar2;
    }
  }
  iVar3 = FUN_8003687c(param_1,&local_38,&local_30,auStack52);
  if (iVar3 != 0) {
    if (((*(char *)(param_2 + 0x354) == '\0') ||
        (((local_30 != 3 && (local_30 != 2)) || ((*(ushort *)(DAT_803ddd54 + 0xfa) & 0x10) == 0))))
       || (iVar3 != 5)) {
      if (DAT_803ddd4c == 0) {
        FUN_8000bb18(param_1,0x95);
        iVar3 = *(int *)(*(int *)(*(int *)(param_1 + 0x7c) + *(char *)(param_1 + 0xad) * 4) + 0x50)
                + local_30 * 0x10;
        DAT_803ad164 = FLOAT_803dcdd8 + *(float *)(iVar3 + 4);
        DAT_803ad168 = *(float *)(iVar3 + 8);
        DAT_803ad16c = FLOAT_803dcddc + *(float *)(iVar3 + 0xc);
        (**(code **)(*DAT_803dca88 + 8))(param_1,0x328,&DAT_803ad158,0x200001,0xffffffff,0);
        DAT_803ad164 = DAT_803ad164 - *(float *)(param_1 + 0x18);
        DAT_803ad168 = DAT_803ad168 - *(float *)(param_1 + 0x1c);
        DAT_803ad16c = DAT_803ad16c - *(float *)(param_1 + 0x20);
        DAT_803ad160 = FLOAT_803e6818;
        DAT_803ad158 = 0;
        DAT_803ad15a = 0;
        DAT_803ad15c = 0;
        iVar3 = FUN_800221a0(0,0x9b);
        local_28 = local_28 + iVar3;
        iVar3 = FUN_800221a0(0,0x9b);
        local_24 = local_24 + iVar3;
        (**(code **)(*DAT_803ddd48 + 4))(param_1,0,&DAT_803ad158,1,0xffffffff,&local_2c);
        DAT_803ddd4c = 0x3c;
      }
    }
    else {
      iVar3 = *(int *)(*(int *)(*(int *)(param_1 + 0x7c) + *(char *)(param_1 + 0xad) * 4) + 0x50) +
              local_30 * 0x10;
      DAT_803ad164 = FLOAT_803dcdd8 + *(float *)(iVar3 + 4);
      DAT_803ad168 = *(float *)(iVar3 + 8);
      DAT_803ad16c = FLOAT_803dcddc + *(float *)(iVar3 + 0xc);
      FUN_8000bb18(param_1,0x8c);
      FUN_8000bb18(param_1,0x94);
      (**(code **)(*DAT_803dca88 + 8))(param_1,0x4b2,&DAT_803ad158,0x200001,0xffffffff,0);
      (**(code **)(*DAT_803dca88 + 8))(param_1,0x4b3,&DAT_803ad158,0x200001,0xffffffff,0);
      *(undefined *)(param_2 + 0x354) = 0;
      if (*(char *)(param_2 + 0x354) < '\x01') {
        *(undefined *)(param_2 + 0x354) = 0;
        *(ushort *)(DAT_803ddd54 + 0xfa) = *(ushort *)(DAT_803ddd54 + 0xfa) & 0xffef;
        *(ushort *)(DAT_803ddd54 + 0xfa) = *(ushort *)(DAT_803ddd54 + 0xfa) | 8;
      }
      *(undefined *)(param_2 + 0x34f) = 5;
    }
    if (*(char *)(param_2 + 0x354) < '\x01') {
      *(undefined *)(param_2 + 0x354) = 0;
    }
    FUN_800378c4(local_38,0xe0001,param_1,0);
  }
  return;
}

