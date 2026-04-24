// Function: FUN_802795cc
// Entry: 802795cc
// Size: 400 bytes

void FUN_802795cc(int param_1,byte param_2)

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
  if ((&DAT_803cab92)[uVar6 * 2] == 1) {
    if (*(byte *)(param_1 + 0x10c) == param_2) {
      return;
    }
    FUN_802794ec(param_1);
  }
  (&DAT_803cab92)[uVar6 * 2] = 1;
  uVar4 = (uint)param_2;
  (&DAT_803cab90)[uVar6 * 4] = 0xff;
  pbVar1 = &DAT_803cac90 + uVar4;
  bVar2 = *pbVar1;
  (&DAT_803cab91)[uVar6 * 4] = bVar2;
  if (bVar2 == 0xff) {
    uVar6 = (uint)DAT_803de2fc;
    uVar5 = (ushort)param_2;
    if (uVar6 == 0xffff) {
      *(undefined2 *)(&DAT_803cad90 + uVar4 * 4) = 0xffff;
      *(undefined2 *)(&DAT_803cad92 + uVar4 * 4) = 0xffff;
      DAT_803de2fc = uVar5;
    }
    else if (uVar4 < uVar6) {
      *(ushort *)(&DAT_803cad90 + uVar4 * 4) = DAT_803de2fc;
      *(undefined2 *)(&DAT_803cad92 + uVar4 * 4) = 0xffff;
      *(ushort *)(&DAT_803cad92 + uVar6 * 4) = uVar5;
      DAT_803de2fc = uVar5;
    }
    else {
      while ((uVar7 = uVar6, uVar7 != 0xffff && (uVar7 <= uVar4))) {
        unaff_r29 = uVar7;
        uVar6 = (uint)*(ushort *)(&DAT_803cad90 + uVar7 * 4);
      }
      *(ushort *)(&DAT_803cad90 + (unaff_r29 & 0xffff) * 4) = (ushort)param_2;
      *(short *)(&DAT_803cad92 + uVar4 * 4) = (short)unaff_r29;
      *(short *)(&DAT_803cad90 + uVar4 * 4) = (short)uVar7;
      if (uVar7 != 0xffff) {
        *(ushort *)(&DAT_803cad92 + uVar7 * 4) = (ushort)param_2;
      }
    }
  }
  else {
    (&DAT_803cab90)[(uint)*pbVar1 * 4] = bVar3;
  }
  *pbVar1 = bVar3;
  *(byte *)(param_1 + 0x10c) = param_2;
  FUN_8028327c(*(uint *)(param_1 + 0xf4) & 0xff,uVar4 << 0x18 | *(uint *)(param_1 + 0x110) >> 0xf);
  return;
}

