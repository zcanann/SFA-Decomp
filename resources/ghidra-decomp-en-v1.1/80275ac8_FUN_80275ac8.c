// Function: FUN_80275ac8
// Entry: 80275ac8
// Size: 776 bytes

undefined4 FUN_80275ac8(int param_1,uint *param_2)

{
  bool bVar2;
  uint uVar1;
  uint local_18 [2];
  
  local_18[0] = param_2[1] >> 0x10;
  if (local_18[0] != 0) {
    if ((*param_2 >> 8 & 1) == 0) {
      *(uint *)(param_1 + 0x118) = *(uint *)(param_1 + 0x118) & 0xfffffffb;
      *(undefined4 *)(param_1 + 0x114) = *(undefined4 *)(param_1 + 0x114);
    }
    else {
      if ((*(uint *)(param_1 + 0x118) & 8) != 0) {
        if ((*(uint *)(param_1 + 0x114) & 0x100) == 0) {
          return 0;
        }
        *(uint *)(param_1 + 0x118) = *(uint *)(param_1 + 0x118);
        *(uint *)(param_1 + 0x114) = *(uint *)(param_1 + 0x114) | 0x400;
      }
      *(uint *)(param_1 + 0x118) = *(uint *)(param_1 + 0x118) | 4;
    }
    if ((*param_2 >> 0x18 & 1) == 0) {
      *(uint *)(param_1 + 0x118) = *(uint *)(param_1 + 0x118) & 0xfffbffff;
      *(undefined4 *)(param_1 + 0x114) = *(undefined4 *)(param_1 + 0x114);
    }
    else {
      if (((*(uint *)(param_1 + 0x118) & 0x20) == 0) &&
         (bVar2 = FUN_802839b8(*(uint *)(param_1 + 0xf4) & 0xff), !bVar2)) {
        return 0;
      }
      *(uint *)(param_1 + 0x118) = *(uint *)(param_1 + 0x118) | 0x40000;
    }
    if ((*param_2 >> 0x10 & 1) != 0) {
      uVar1 = FUN_802835c0();
      local_18[0] = (uVar1 & 0xffff) - ((uVar1 & 0xffff) / local_18[0]) * local_18[0];
    }
    if (local_18[0] == 0xffff) {
      *(undefined4 *)(param_1 + 0x9c) = 0xffffffff;
      *(undefined4 *)(param_1 + 0x98) = 0xffffffff;
    }
    else {
      if ((param_2[1] >> 8 & 1) == 0) {
        FUN_802836f4(local_18,param_1);
        if ((param_2[1] & 1) == 0) {
          *(uint *)(param_1 + 0x9c) = *(uint *)(param_1 + 0xa4) + local_18[0];
          *(uint *)(param_1 + 0x98) =
               *(int *)(param_1 + 0xa0) + (uint)CARRY4(*(uint *)(param_1 + 0xa4),local_18[0]);
        }
        else {
          *(uint *)(param_1 + 0x9c) = local_18[0];
          *(undefined4 *)(param_1 + 0x98) = 0;
        }
      }
      else {
        FUN_802836e4((int *)local_18);
        uVar1 = DAT_803def60;
        if ((param_2[1] & 1) == 0) {
          bVar2 = CARRY4(DAT_803def64,local_18[0]);
          *(uint *)(param_1 + 0x9c) = DAT_803def64 + local_18[0];
          *(uint *)(param_1 + 0x98) = uVar1 + bVar2;
        }
        else {
          *(uint *)(param_1 + 0x9c) = *(uint *)(param_1 + 0x94) + local_18[0];
          *(uint *)(param_1 + 0x98) =
               *(int *)(param_1 + 0x90) + (uint)CARRY4(*(uint *)(param_1 + 0x94),local_18[0]);
        }
      }
      if ((uint)(DAT_803def64 < *(uint *)(param_1 + 0x9c)) + *(int *)(param_1 + 0x98) <=
          DAT_803def60) {
        *(uint *)(param_1 + 0xa4) = *(uint *)(param_1 + 0x9c);
        *(int *)(param_1 + 0xa0) = *(int *)(param_1 + 0x98);
        *(undefined4 *)(param_1 + 0x9c) = 0;
        *(undefined4 *)(param_1 + 0x98) = 0;
      }
    }
    if (*(int *)(param_1 + 0x9c) != 0 || *(int *)(param_1 + 0x98) != 0) {
      if (*(int *)(param_1 + 0x9c) != -1 || *(int *)(param_1 + 0x98) != -1) {
        FUN_80278f74(param_1);
      }
      FUN_802791fc(param_1,1);
      return 1;
    }
  }
  return 0;
}

