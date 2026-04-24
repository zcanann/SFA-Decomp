// Function: FUN_80214418
// Entry: 80214418
// Size: 1020 bytes

/* WARNING: Removing unreachable block (ram,0x80214610) */

void FUN_80214418(double param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 uint param_9,int param_10,undefined4 param_11,undefined4 param_12,
                 undefined4 param_13,undefined4 *param_14,int param_15,undefined4 param_16)

{
  float fVar1;
  int iVar2;
  uint uVar3;
  double dVar4;
  double dVar5;
  double dVar6;
  int local_38;
  uint uStack_34;
  int local_30;
  undefined4 local_2c;
  int local_28;
  int local_24;
  undefined4 local_20;
  
  fVar1 = FLOAT_803e7450;
  local_2c = DAT_802c2cd0;
  local_28 = DAT_802c2cd4;
  local_24 = DAT_802c2cd8;
  local_20 = DAT_802c2cdc;
  if (DAT_803de9cc != 0) {
    DAT_803de9cc = DAT_803de9cc + -1;
  }
  dVar6 = (double)*(float *)(DAT_803de9d8 + 1000);
  dVar5 = (double)FLOAT_803e7450;
  if (dVar5 < dVar6) {
    param_1 = (double)FLOAT_803dc074;
    *(float *)(DAT_803de9d8 + 1000) =
         (float)(param_1 * (double)*(float *)(DAT_803de9d8 + 0x3ec) + dVar6);
    dVar4 = (double)*(float *)(DAT_803de9d8 + 1000);
    if (dVar5 <= dVar4) {
      param_1 = (double)FLOAT_803e74b8;
      if (param_1 < dVar4) {
        *(float *)(DAT_803de9d8 + 1000) = (float)(param_1 - (double)(float)(dVar4 - param_1));
        *(float *)(DAT_803de9d8 + 0x3ec) = -*(float *)(DAT_803de9d8 + 0x3ec);
      }
    }
    else {
      *(float *)(DAT_803de9d8 + 1000) = fVar1;
    }
  }
  iVar2 = FUN_80036974(param_9,&local_38,&local_30,&uStack_34);
  if (iVar2 != 0) {
    if (((*(char *)(param_10 + 0x354) == '\0') ||
        (((local_30 != 3 && (local_30 != 2)) || ((*(ushort *)(DAT_803de9d4 + 0xfa) & 0x10) == 0))))
       || (iVar2 != 5)) {
      if (DAT_803de9cc == 0) {
        FUN_8000bb38(param_9,0x95);
        iVar2 = *(int *)(*(int *)(*(int *)(param_9 + 0x7c) + *(char *)(param_9 + 0xad) * 4) + 0x50)
                + local_30 * 0x10;
        DAT_803addc4 = FLOAT_803dda58 + *(float *)(iVar2 + 4);
        DAT_803addc8 = *(float *)(iVar2 + 8);
        DAT_803addcc = FLOAT_803dda5c + *(float *)(iVar2 + 0xc);
        (**(code **)(*DAT_803dd708 + 8))(param_9,0x328,&DAT_803addb8,0x200001,0xffffffff,0);
        DAT_803addc4 = DAT_803addc4 - *(float *)(param_9 + 0x18);
        DAT_803addc8 = DAT_803addc8 - *(float *)(param_9 + 0x1c);
        DAT_803addcc = DAT_803addcc - *(float *)(param_9 + 0x20);
        DAT_803addc0 = FLOAT_803e74b0;
        DAT_803addb8 = 0;
        DAT_803addba = 0;
        DAT_803addbc = 0;
        uVar3 = FUN_80022264(0,0x9b);
        local_28 = local_28 + uVar3;
        uVar3 = FUN_80022264(0,0x9b);
        local_24 = local_24 + uVar3;
        param_13 = 0xffffffff;
        param_14 = &local_2c;
        param_15 = *DAT_803de9c8;
        param_1 = (double)(**(code **)(param_15 + 4))(param_9,0,&DAT_803addb8,1);
        DAT_803de9cc = 0x3c;
      }
    }
    else {
      iVar2 = *(int *)(*(int *)(*(int *)(param_9 + 0x7c) + *(char *)(param_9 + 0xad) * 4) + 0x50) +
              local_30 * 0x10;
      DAT_803addc4 = FLOAT_803dda58 + *(float *)(iVar2 + 4);
      DAT_803addc8 = *(float *)(iVar2 + 8);
      DAT_803addcc = FLOAT_803dda5c + *(float *)(iVar2 + 0xc);
      FUN_8000bb38(param_9,0x8c);
      FUN_8000bb38(param_9,0x94);
      (**(code **)(*DAT_803dd708 + 8))(param_9,0x4b2,&DAT_803addb8,0x200001,0xffffffff,0);
      param_13 = 0xffffffff;
      param_14 = (undefined4 *)0x0;
      param_15 = *DAT_803dd708;
      param_1 = (double)(**(code **)(param_15 + 8))(param_9,0x4b3,&DAT_803addb8,0x200001);
      *(undefined *)(param_10 + 0x354) = 0;
      if (*(char *)(param_10 + 0x354) < '\x01') {
        *(undefined *)(param_10 + 0x354) = 0;
        *(ushort *)(DAT_803de9d4 + 0xfa) = *(ushort *)(DAT_803de9d4 + 0xfa) & 0xffef;
        *(ushort *)(DAT_803de9d4 + 0xfa) = *(ushort *)(DAT_803de9d4 + 0xfa) | 8;
      }
      *(undefined *)(param_10 + 0x34f) = 5;
    }
    if (*(char *)(param_10 + 0x354) < '\x01') {
      *(undefined *)(param_10 + 0x354) = 0;
    }
    FUN_800379bc(param_1,dVar5,dVar6,param_4,param_5,param_6,param_7,param_8,local_38,0xe0001,
                 param_9,0,param_13,param_14,param_15,param_16);
  }
  return;
}

