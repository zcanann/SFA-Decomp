// Function: FUN_80279d30
// Entry: 80279d30
// Size: 400 bytes

void FUN_80279d30(int param_1,byte param_2)

{
  byte *pbVar1;
  byte bVar2;
  byte bVar3;
  uint uVar4;
  ushort uVar5;
  uint uVar6;
  uint uVar7;
  uint unaff_r29;
  
  bVar3 = (byte)*(uint *)(param_1 + 0xf4);
  uVar6 = *(uint *)(param_1 + 0xf4) & 0xff;
  if ((&DAT_803cb7f2)[uVar6 * 2] == 1) {
    if (*(byte *)(param_1 + 0x10c) == param_2) {
      return;
    }
    FUN_80279c50(param_1);
  }
  (&DAT_803cb7f2)[uVar6 * 2] = 1;
  uVar4 = (uint)param_2;
  (&DAT_803cb7f0)[uVar6 * 4] = 0xff;
  pbVar1 = &DAT_803cb8f0 + uVar4;
  bVar2 = *pbVar1;
  (&DAT_803cb7f1)[uVar6 * 4] = bVar2;
  if (bVar2 == 0xff) {
    uVar6 = (uint)DAT_803def7c;
    uVar5 = (ushort)param_2;
    if (uVar6 == 0xffff) {
      *(undefined2 *)(&DAT_803cb9f0 + uVar4 * 4) = 0xffff;
      *(undefined2 *)(&DAT_803cb9f2 + uVar4 * 4) = 0xffff;
      DAT_803def7c = uVar5;
    }
    else if (uVar4 < uVar6) {
      *(ushort *)(&DAT_803cb9f0 + uVar4 * 4) = DAT_803def7c;
      *(undefined2 *)(&DAT_803cb9f2 + uVar4 * 4) = 0xffff;
      *(ushort *)(&DAT_803cb9f2 + uVar6 * 4) = uVar5;
      DAT_803def7c = uVar5;
    }
    else {
      while ((uVar7 = uVar6, uVar7 != 0xffff && (uVar7 <= uVar4))) {
        unaff_r29 = uVar7;
        uVar6 = (uint)*(ushort *)(&DAT_803cb9f0 + uVar7 * 4);
      }
      *(ushort *)(&DAT_803cb9f0 + (unaff_r29 & 0xffff) * 4) = (ushort)param_2;
      *(short *)(&DAT_803cb9f2 + uVar4 * 4) = (short)unaff_r29;
      *(short *)(&DAT_803cb9f0 + uVar4 * 4) = (short)uVar7;
      if (uVar7 != 0xffff) {
        *(ushort *)(&DAT_803cb9f2 + uVar7 * 4) = (ushort)param_2;
      }
    }
  }
  else {
    (&DAT_803cb7f0)[(uint)*pbVar1 * 4] = bVar3;
  }
  *pbVar1 = bVar3;
  *(byte *)(param_1 + 0x10c) = param_2;
  FUN_802839e0(*(uint *)(param_1 + 0xf4) & 0xff,uVar4 << 0x18 | *(uint *)(param_1 + 0x110) >> 0xf);
  return;
}

