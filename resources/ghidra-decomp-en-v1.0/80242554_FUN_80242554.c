// Function: FUN_80242554
// Entry: 80242554
// Size: 680 bytes

void FUN_80242554(undefined4 *param_1)

{
  bool bVar1;
  undefined4 uVar2;
  undefined4 uVar3;
  undefined4 uVar4;
  undefined4 uVar5;
  uint uVar6;
  undefined4 *puVar7;
  undefined auStack744 [416];
  undefined2 local_148;
  undefined2 local_146;
  
  FUN_8007d6dc(s___________________________Contex_8032c7d0,param_1);
  uVar6 = 0;
  puVar7 = param_1;
  do {
    FUN_8007d6dc(s_r__2d___0x_08x___14d__r__2d___0x_8032c814,uVar6,*puVar7,*puVar7,uVar6 + 0x10,
                 puVar7[0x10],puVar7[0x10]);
    puVar7 = puVar7 + 1;
    uVar6 = uVar6 + 1;
  } while (uVar6 < 0x10);
  FUN_8007d6dc(s_LR___0x_08x_CR___0x_08x_8032c844,param_1[0x21],param_1[0x20]);
  FUN_8007d6dc(s_SRR0___0x_08x_SRR1___0x_08x_8032c874,param_1[0x66],param_1[0x67]);
  FUN_8007d6dc(s__GQRs___________8032c8a4);
  uVar6 = 0;
  puVar7 = param_1;
  do {
    FUN_8007d6dc(s_gqr_d___0x_08x_gqr_d___0x_08x_8032c8b8,uVar6,puVar7[0x69],uVar6 + 4,puVar7[0x6d])
    ;
    puVar7 = puVar7 + 1;
    uVar6 = uVar6 + 1;
  } while (uVar6 < 4);
  if ((*(ushort *)((int)param_1 + 0x1a2) & 1) != 0) {
    uVar3 = FUN_8024377c();
    uVar2 = DAT_800000d4;
    local_148 = 0;
    local_146 = 0;
    if (auStack744 == DAT_800000d8) {
      DAT_800000d8 = (undefined *)0x0;
    }
    FUN_802422ac(auStack744);
    FUN_8007d6dc(s__FPRs___________8032c8dc);
    uVar6 = 0;
    puVar7 = param_1;
    do {
      uVar4 = FUN_80285fb4(*(undefined8 *)(puVar7 + 0x26));
      uVar5 = FUN_80285fb4(*(undefined8 *)(puVar7 + 0x24));
      FUN_8007d6dc(s_fr_d____d_fr_d____d_8032c8f0,uVar6,uVar5,uVar6 + 1,uVar4);
      puVar7 = puVar7 + 4;
      uVar6 = uVar6 + 2;
    } while (uVar6 < 0x20);
    FUN_8007d6dc(s__PSFs___________8032c90c);
    uVar6 = 0;
    puVar7 = param_1;
    do {
      uVar4 = FUN_80285fb4(*(undefined8 *)(puVar7 + 0x74));
      uVar5 = FUN_80285fb4(*(undefined8 *)(puVar7 + 0x72));
      FUN_8007d6dc(s_ps_d___0x_x_ps_d___0x_x_8032c920,uVar6,uVar5,uVar6 + 1,uVar4);
      puVar7 = puVar7 + 4;
      uVar6 = uVar6 + 2;
    } while (uVar6 < 0x20);
    local_148 = 0;
    local_146 = 0;
    if (auStack744 == DAT_800000d8) {
      DAT_800000d8 = (undefined *)0x0;
    }
    FUN_802422ac(uVar2);
    FUN_802437a4(uVar3);
  }
  FUN_8007d6dc(s__Address__Back_Chain_LR_Save_8032c940);
  puVar7 = (undefined4 *)param_1[1];
  uVar6 = 0;
  while (((puVar7 != (undefined4 *)0x0 && (puVar7 != (undefined4 *)0xffffffff)) &&
         (bVar1 = uVar6 < 0x10, uVar6 = uVar6 + 1, bVar1))) {
    FUN_8007d6dc(s_0x_08x__0x_08x_0x_08x_8032c968,puVar7,*puVar7,puVar7[1]);
    puVar7 = (undefined4 *)*puVar7;
  }
  return;
}

