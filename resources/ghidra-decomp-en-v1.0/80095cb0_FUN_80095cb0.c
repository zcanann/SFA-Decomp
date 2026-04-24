// Function: FUN_80095cb0
// Entry: 80095cb0
// Size: 860 bytes

/* WARNING: Removing unreachable block (ram,0x80095fec) */

void FUN_80095cb0(void)

{
  undefined4 uVar1;
  int iVar2;
  undefined4 *puVar3;
  float *pfVar4;
  int iVar5;
  int iVar6;
  int iVar7;
  undefined4 uVar8;
  undefined8 in_f31;
  double dVar9;
  undefined8 uVar10;
  undefined2 local_48;
  undefined2 local_46;
  undefined2 local_44;
  undefined4 local_40;
  undefined4 local_3c;
  undefined4 local_38;
  undefined4 local_34;
  undefined auStack8 [8];
  
  uVar8 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  uVar10 = FUN_802860d4();
  uVar1 = (undefined4)((ulonglong)uVar10 >> 0x20);
  if ((((DAT_803dd23c != 0) || (DAT_803dd22c != 0)) || (DAT_803dd234 != 0)) || (DAT_803dd224 != 0))
  {
    FUN_80258b24(0);
    if (DAT_803dd23c != 0) {
      FUN_8007caf4(DAT_803dd21c);
    }
    iVar2 = 0;
    iVar5 = 0;
    iVar6 = 0;
    iVar7 = 0;
    do {
      puVar3 = (undefined4 *)(DAT_803dd238 + iVar5);
      if (*(ushort *)((int)puVar3 + 0x16) != 0) {
        FUN_8005d118(uVar1,0xff,0xff,0xff,*(ushort *)((int)puVar3 + 0x16) & 0xff);
        local_3c = *puVar3;
        local_38 = puVar3[1];
        local_34 = puVar3[2];
        local_40 = puVar3[4];
        local_48 = *(undefined2 *)(puVar3 + 5);
        local_44 = 0;
        local_46 = 0;
        FUN_8000e820((double)FLOAT_803df2ec,(double)FLOAT_803df300,uVar1,(int)uVar10,&local_48,0);
        FUN_8007d670();
        FUN_8005cf8c(DAT_803dd24c + iVar7,DAT_803dd248 + iVar6,2);
      }
      iVar5 = iVar5 + 0x1c;
      iVar6 = iVar6 + 0x20;
      iVar7 = iVar7 + 0x40;
      iVar2 = iVar2 + 1;
    } while (iVar2 < 0x1e);
    iVar2 = 0;
    if (DAT_803dd234 != 0) {
      FUN_8007bd8c(DAT_803dd218,DAT_803dd214);
      FUN_80257e74(9,DAT_803dd200,0xc);
      FUN_80257e74(0xd,DAT_803dd1fc,8);
      FUN_802573f8();
      FUN_80256978(0,1);
      FUN_80256978(1,1);
      FUN_80256978(9,3);
      FUN_80256978(0xb,3);
      FUN_80256978(0xd,3);
    }
    iVar5 = 0;
    dVar9 = (double)FLOAT_803df2ec;
    do {
      if ((double)*(float *)(DAT_803dd230 + iVar5 + 0x10) < dVar9) {
        FUN_80095164();
      }
      iVar5 = iVar5 + 0x3c;
      iVar2 = iVar2 + 1;
    } while (iVar2 < 10);
    if (DAT_803dd224 != 0) {
      FUN_80094f7c();
    }
    iVar2 = 0;
    iVar5 = 0;
    do {
      pfVar4 = (float *)(DAT_803dd220 + iVar5);
      if (*(char *)(pfVar4 + 6) != -1) {
        FUN_8025889c(0xb8,2,1);
        write_volatile_4(0xcc008000,*pfVar4 - FLOAT_803dcdd8);
        write_volatile_4(0xcc008000,pfVar4[1]);
        write_volatile_4(0xcc008000,pfVar4[2] - FLOAT_803dcddc);
      }
      iVar5 = iVar5 + 0x1c;
      iVar2 = iVar2 + 1;
    } while (iVar2 < 0x1e);
    if (DAT_803dd22c != 0) {
      FUN_8007c664(DAT_803dd210);
    }
    iVar2 = 0;
    iVar5 = 0;
    iVar7 = 0;
    iVar6 = 0;
    do {
      puVar3 = (undefined4 *)(DAT_803dd228 + iVar5);
      if ((*(ushort *)(puVar3 + 5) != 0) && (*(char *)(puVar3 + 6) == '\0')) {
        FUN_8005d118(uVar1,0xff,0xff,0xff,*(ushort *)(puVar3 + 5) & 0xff);
        local_3c = *puVar3;
        local_38 = puVar3[1];
        local_34 = puVar3[2];
        local_40 = puVar3[4];
        local_48 = *(undefined2 *)((int)puVar3 + 0x16);
        local_44 = 0;
        local_46 = 0;
        FUN_8000e820((double)FLOAT_803df2ec,(double)FLOAT_803df300,uVar1,(int)uVar10,&local_48,0);
        FUN_8007d670();
        FUN_8005cf8c(DAT_803dd244 + iVar6,DAT_803dd240 + iVar7,2);
      }
      iVar5 = iVar5 + 0x1c;
      iVar7 = iVar7 + 0x20;
      iVar6 = iVar6 + 0x40;
      iVar2 = iVar2 + 1;
    } while (iVar2 < 0x1e);
    FUN_800542f4();
  }
  __psq_l0(auStack8,uVar8);
  __psq_l1(auStack8,uVar8);
  FUN_80286120();
  return;
}

