// Function: FUN_8000b370
// Entry: 8000b370
// Size: 352 bytes

void FUN_8000b370(int param_1,undefined4 *param_2,int param_3)

{
  uint uVar1;
  undefined4 uVar2;
  undefined uVar3;
  uint local_38;
  undefined4 local_34;
  undefined4 local_30;
  uint local_2c;
  uint local_28;
  undefined4 local_24;
  undefined4 local_20;
  undefined4 local_1c;
  
  local_38 = DAT_802c1a68;
  local_34 = DAT_802c1a6c;
  local_30 = DAT_802c1a70;
  local_2c = DAT_802c1a74;
  local_28 = DAT_802c1a78;
  local_24 = DAT_802c1a7c;
  local_20 = DAT_802c1a80;
  local_1c = DAT_802c1a84;
  if (param_2 != (undefined4 *)0x0) {
    if (param_2[3] == 5) {
      FUN_80023800(param_2[2]);
      *param_2 = 0xffffffff;
      param_2[1] = 0xffffffff;
      param_2[2] = 0;
      *(undefined *)(param_2 + 4) = 0xff;
      param_2[3] = 0;
      *(undefined2 *)((int)param_2 + 0x12) = 0;
      param_2[8] = FLOAT_803de560;
    }
    else {
      if (*(ushort *)(param_3 + 6) != 0xffffffff) {
        local_2c = (uint)*(ushort *)(param_3 + 6) << 0x10;
        local_38 = DAT_802c1a68 | 2;
      }
      uVar1 = (uint)*(byte *)(param_3 + 0xc);
      if (uVar1 == 0xffffffff) {
        uVar1 = 0x7f;
      }
      local_28 = DAT_802c1a78 & 0xffffff;
      local_2c = local_2c & 0xffff0000;
      local_38 = local_38 | 4;
      uVar2 = FUN_8027b9dc(*(undefined *)(param_1 + 2),*(undefined2 *)(param_3 + 2),param_2[2],
                           &local_38,0);
      FUN_80272720(uVar1,500,uVar2,0);
      param_2[3] = 1;
      param_2[1] = uVar2;
      uVar3 = FUN_8026c41c(uVar2);
      *(undefined *)(param_2 + 4) = uVar3;
    }
  }
  return;
}

