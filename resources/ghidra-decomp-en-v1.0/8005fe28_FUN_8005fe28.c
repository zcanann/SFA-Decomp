// Function: FUN_8005fe28
// Entry: 8005fe28
// Size: 1640 bytes

/* WARNING: Removing unreachable block (ram,0x80060470) */

void FUN_8005fe28(void)

{
  int iVar1;
  int iVar2;
  float fVar3;
  float fVar4;
  byte bVar8;
  int iVar5;
  int iVar6;
  char cVar9;
  undefined4 uVar7;
  int iVar10;
  int *piVar11;
  undefined uVar12;
  int *piVar13;
  undefined4 uVar14;
  double dVar15;
  undefined8 in_f31;
  double dVar16;
  undefined4 local_c8;
  undefined4 local_c4;
  undefined local_c0;
  undefined local_bf;
  undefined local_be [2];
  int local_bc;
  int local_b8;
  int local_b4;
  float local_b0;
  float local_ac;
  float local_a8;
  undefined4 local_a4;
  undefined4 local_a0;
  undefined4 local_9c;
  undefined auStack152 [4];
  undefined auStack148 [4];
  undefined auStack144 [4];
  undefined auStack140 [12];
  float local_80;
  float local_70;
  float local_60;
  undefined4 local_58;
  uint uStack84;
  longlong local_50;
  double local_48;
  longlong local_40;
  undefined4 local_38;
  uint uStack52;
  longlong local_30;
  undefined auStack8 [8];
  
  uVar14 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  FUN_802860d8();
  local_c4 = DAT_803e8440;
  FUN_80258b24(0);
  FUN_8000fb00();
  FUN_802573f8();
  FUN_80256978(9,1);
  FUN_80256978(0xd,1);
  FUN_800799c0();
  FUN_800794e0();
  FUN_80079804();
  local_c8 = local_c4;
  dVar15 = (double)FLOAT_803debcc;
  FUN_8025c2d4(dVar15,dVar15,dVar15,dVar15,0,&local_c8);
  FUN_800789ac();
  uVar12 = 0xff;
  DAT_803dce10 = 0;
  DAT_803dce14 = 0;
  bVar8 = FUN_8008919c(2);
  if ((bVar8 != 0) && ((DAT_803dcde8 & 0x40) != 0)) {
    iVar5 = FUN_8000f54c();
    FUN_800897d4(0,auStack152,auStack148,auStack144);
    local_a4 = *(undefined4 *)(iVar5 + 0x20);
    local_a0 = *(undefined4 *)(iVar5 + 0x24);
    local_9c = *(undefined4 *)(iVar5 + 0x28);
    dVar15 = (double)FUN_8024782c(auStack152,&local_a4);
    if ((double)FLOAT_803debcc < dVar15) {
      FUN_80089134(auStack140);
      FUN_8000edac((double)local_80,(double)local_70,(double)local_60,(double)FLOAT_803debd4,
                   &local_a8,&local_ac,&local_b0);
      FUN_8000ea78((double)local_a8,(double)local_ac,(double)local_b0,&local_b4,&local_b8,&local_bc)
      ;
      DAT_803dce08 = local_b4 + -0x10;
      DAT_803dce10 = 0x20;
      DAT_803dce0c = local_b8 + -0x10;
      DAT_803dce14 = 0x20;
      if (DAT_803dce08 < 0) {
        DAT_803dce08 = 0;
      }
      else if (0x280 < DAT_803dce08) {
        DAT_803dce08 = 0x280;
      }
      if (DAT_803dce0c < 0) {
        DAT_803dce0c = 0;
      }
      else if (0x1e0 < DAT_803dce0c) {
        DAT_803dce0c = 0x1e0;
      }
      if (0x280 < DAT_803dce08 + 0x20) {
        DAT_803dce10 = 0x280 - DAT_803dce08;
      }
      if (0x1e0 < DAT_803dce0c + 0x20) {
        DAT_803dce14 = 0x1e0 - DAT_803dce0c;
      }
      uStack84 = 0;
      iVar10 = 0;
      piVar11 = &DAT_8030e634;
      do {
        iVar6 = FUN_8006fdf8(local_b4 + *piVar11,local_b8 + piVar11[1],iVar10);
        if ((local_bc <= iVar6) && (cVar9 = FUN_8011f344(), cVar9 == '\0')) {
          uStack84 = uStack84 + 1;
        }
        piVar11 = piVar11 + 2;
        iVar10 = iVar10 + 1;
      } while (iVar10 < 5);
      local_58 = 0x43300000;
      fVar3 = (float)((double)CONCAT44(0x43300000,uStack84) - DOUBLE_803dec48) / FLOAT_803debe4 -
              FLOAT_803dce18;
      fVar4 = FLOAT_803dec30;
      if ((fVar3 <= FLOAT_803dec30) && (fVar4 = fVar3, fVar3 < FLOAT_803dec34)) {
        fVar4 = FLOAT_803dec34;
      }
      FLOAT_803dce18 = FLOAT_803dce18 + fVar4;
      dVar15 = (double)(float)(dVar15 * (double)FLOAT_803dce18);
      if ((double)FLOAT_803debcc < dVar15) {
        FUN_80246eb4(iVar5,auStack140,auStack140);
        FUN_8025d0a8(auStack140,0);
        FUN_8025d124(0);
        uVar7 = FUN_8008912c();
        FUN_8004c2e4(uVar7,0);
        FUN_800898c8(0,&local_c0,&local_bf,local_be);
        uStack84 = (uint)bVar8;
        local_58 = 0x43300000;
        dVar15 = (double)(float)((double)(float)((double)CONCAT44(0x43300000,uStack84) -
                                                DOUBLE_803dec48) * dVar15);
        local_50 = (longlong)(int)((double)FLOAT_803debfc * dVar15);
        FUN_800799e4(local_c0,local_bf,local_be[0],(int)((double)FLOAT_803debfc * dVar15));
        iVar5 = (int)-(float)((double)FLOAT_803dec38 * dVar15 - (double)FLOAT_803debd8);
        local_48 = (double)(longlong)iVar5;
        uVar12 = (undefined)iVar5;
        dVar16 = (double)((float)((double)FLOAT_803dec3c * dVar15) * FLOAT_803dec40);
        FUN_8025889c(0x80,2,4);
        dVar15 = -dVar16;
        write_volatile_4(0xcc008000,(float)dVar15);
        write_volatile_4(0xcc008000,(float)dVar15);
        write_volatile_4(0xcc008000,FLOAT_803debcc);
        write_volatile_4(0xcc008000,FLOAT_803debcc);
        write_volatile_4(0xcc008000,FLOAT_803debcc);
        write_volatile_4(0xcc008000,(float)dVar16);
        write_volatile_4(0xcc008000,(float)dVar15);
        write_volatile_4(0xcc008000,FLOAT_803debcc);
        write_volatile_4(0xcc008000,FLOAT_803debdc);
        write_volatile_4(0xcc008000,FLOAT_803debcc);
        write_volatile_4(0xcc008000,(float)dVar16);
        write_volatile_4(0xcc008000,(float)dVar16);
        write_volatile_4(0xcc008000,FLOAT_803debcc);
        write_volatile_4(0xcc008000,FLOAT_803debdc);
        write_volatile_4(0xcc008000,FLOAT_803debdc);
        write_volatile_4(0xcc008000,(float)dVar15);
        write_volatile_4(0xcc008000,(float)dVar16);
        write_volatile_4(0xcc008000,FLOAT_803debcc);
        write_volatile_4(0xcc008000,FLOAT_803debcc);
        write_volatile_4(0xcc008000,FLOAT_803debdc);
      }
    }
  }
  DAT_803db634 = uVar12;
  if (DAT_803dce06 != 0) {
    piVar13 = &DAT_80382038;
    piVar11 = piVar13;
    for (iVar5 = 0; iVar5 < (int)(uint)DAT_803dce06; iVar5 = iVar5 + 1) {
      iVar6 = *piVar11;
      FUN_8000edac((double)(*(float *)(iVar6 + 0x10) - FLOAT_803dcdd8),
                   (double)*(float *)(iVar6 + 0x14),
                   (double)(*(float *)(iVar6 + 0x18) - FLOAT_803dcddc),
                   (double)*(float *)(iVar6 + 0x2f4),&local_a8,&local_ac,&local_b0);
      FUN_8000ea78((double)local_a8,(double)local_ac,(double)local_b0,&local_b4,&local_b8,&local_bc)
      ;
      iVar10 = FUN_8006fdf8(local_b4,local_b8,iVar6);
      if ((iVar10 < local_bc) || (cVar9 = FUN_8011f344(), cVar9 != '\0')) {
        *(undefined *)(iVar6 + 0x2fa) = 0xf0;
      }
      else {
        *(undefined *)(iVar6 + 0x2fa) = 0x10;
      }
      piVar11 = piVar11 + 1;
    }
    FUN_8025d124(0x3c);
    FUN_800794e0();
    FUN_800789ac();
    for (iVar5 = 0; iVar5 < (int)(uint)DAT_803dce06; iVar5 = iVar5 + 1) {
      iVar10 = *piVar13;
      if (*(char *)(iVar10 + 0x2f9) != '\0') {
        FUN_8004c2e4(*(undefined4 *)(iVar10 + 0x2e8),0);
        fVar3 = *(float *)(iVar10 + 0x138);
        local_48 = (double)CONCAT44(0x43300000,(uint)*(byte *)(iVar10 + 0x2ec));
        iVar6 = (int)((float)(local_48 - DOUBLE_803dec48) * fVar3);
        local_50 = (longlong)iVar6;
        uStack84 = (uint)*(byte *)(iVar10 + 0x2ed);
        local_58 = 0x43300000;
        iVar1 = (int)((float)((double)CONCAT44(0x43300000,uStack84) - DOUBLE_803dec48) * fVar3);
        local_40 = (longlong)iVar1;
        uStack52 = (uint)*(byte *)(iVar10 + 0x2ee);
        local_38 = 0x43300000;
        iVar2 = (int)((float)((double)CONCAT44(0x43300000,uStack52) - DOUBLE_803dec48) * fVar3);
        local_30 = (longlong)iVar2;
        FUN_800799e4(iVar6,iVar1,iVar2,
                     (int)((uint)*(byte *)(iVar10 + 0x2ef) * (uint)*(byte *)(iVar10 + 0x2f9)) >> 8);
        FUN_8025889c(0x80,2,4);
        write_volatile_4(0xcc008000,*(float *)(iVar10 + 0x1c) - *(float *)(iVar10 + 0x2f0));
        write_volatile_4(0xcc008000,*(float *)(iVar10 + 0x20) - *(float *)(iVar10 + 0x2f0));
        write_volatile_4(0xcc008000,*(undefined4 *)(iVar10 + 0x24));
        write_volatile_4(0xcc008000,FLOAT_803debcc);
        write_volatile_4(0xcc008000,FLOAT_803debcc);
        write_volatile_4(0xcc008000,*(float *)(iVar10 + 0x1c) + *(float *)(iVar10 + 0x2f0));
        write_volatile_4(0xcc008000,*(float *)(iVar10 + 0x20) - *(float *)(iVar10 + 0x2f0));
        write_volatile_4(0xcc008000,*(undefined4 *)(iVar10 + 0x24));
        write_volatile_4(0xcc008000,FLOAT_803debdc);
        write_volatile_4(0xcc008000,FLOAT_803debcc);
        write_volatile_4(0xcc008000,*(float *)(iVar10 + 0x1c) + *(float *)(iVar10 + 0x2f0));
        write_volatile_4(0xcc008000,*(float *)(iVar10 + 0x20) + *(float *)(iVar10 + 0x2f0));
        write_volatile_4(0xcc008000,*(undefined4 *)(iVar10 + 0x24));
        write_volatile_4(0xcc008000,FLOAT_803debdc);
        write_volatile_4(0xcc008000,FLOAT_803debdc);
        write_volatile_4(0xcc008000,*(float *)(iVar10 + 0x1c) - *(float *)(iVar10 + 0x2f0));
        write_volatile_4(0xcc008000,*(float *)(iVar10 + 0x20) + *(float *)(iVar10 + 0x2f0));
        write_volatile_4(0xcc008000,*(undefined4 *)(iVar10 + 0x24));
        write_volatile_4(0xcc008000,FLOAT_803debcc);
        write_volatile_4(0xcc008000,FLOAT_803debdc);
      }
      piVar13 = piVar13 + 1;
    }
    FUN_8025d124(0);
  }
  __psq_l0(auStack8,uVar14);
  __psq_l1(auStack8,uVar14);
  FUN_80286124();
  return;
}

