// Function: FUN_8006f500
// Entry: 8006f500
// Size: 1104 bytes

/* WARNING: Removing unreachable block (ram,0x8006f928) */
/* WARNING: Removing unreachable block (ram,0x8006f930) */

void FUN_8006f500(void)

{
  int iVar1;
  undefined4 uVar2;
  uint uVar3;
  undefined4 *puVar4;
  undefined4 uVar5;
  undefined8 in_f30;
  double dVar6;
  undefined8 in_f31;
  double dVar7;
  uint local_f8;
  uint local_f4;
  undefined auStack240 [48];
  undefined auStack192 [48];
  undefined auStack144 [48];
  undefined auStack96 [48];
  undefined4 local_30;
  uint uStack44;
  undefined auStack24 [16];
  undefined auStack8 [8];
  
  uVar5 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  __psq_st0(auStack24,(int)((ulonglong)in_f30 >> 0x20),0);
  __psq_st1(auStack24,(int)in_f30,0);
  iVar1 = FUN_8002b9ec();
  if (iVar1 != 0) {
    FUN_8000f9b4();
    FUN_8025d124(0);
    FUN_802573f8();
    FUN_80256978(9,1);
    FUN_80256978(0xd,1);
    FUN_802581e0(1);
    FUN_80257f10(0,1,4,0x1e,0,0x7d);
    FUN_8025c2a0(1);
    FUN_8025b6f0(0);
    FUN_80259ea4(4,0,0,0,0,0,2);
    FUN_80259ea4(5,0,0,0,0,0,2);
    FUN_80259e58(0);
    FUN_8025c0c4(0,0,0,0xff);
    FUN_8025b71c(0);
    FUN_8025ba40(0,0xf,0xf,0xf,0xf);
    FUN_8025be8c(0,0x1c);
    FUN_8025bac0(0,7,4,6,7);
    FUN_8025bb44(0,0,0,0,1,0);
    FUN_8025bc04(0,0,0,0,1,0);
    FUN_8025bef8(0,0,0);
    FUN_80258b24(0);
    FUN_8025c584(1,4,5,5);
    FUN_8004c2e4((&DAT_80391dd0)[DAT_803dcff0],0);
    uVar2 = FUN_8000f54c();
    FUN_802472e4(-(double)FLOAT_803dcdd8,(double)FLOAT_803dee20,-(double)FLOAT_803dcddc,auStack96);
    FUN_80246eb4(uVar2,auStack96,auStack144);
    FUN_8025d0a8(auStack144,0);
    FUN_80070310(1,3,0);
    FUN_800702b8(1);
    FUN_8025bff0(7,0,0,7,0);
    iVar1 = 0;
    puVar4 = &DAT_80392de0;
    do {
      uVar3 = (uint)*(byte *)((int)puVar4 + 0x33);
      if (uVar3 != 0) {
        if (*(char *)((int)puVar4 + 0x32) == '\x01') {
          local_f4 = local_f4 & 0xffffff00 | (int)uVar3 >> 2;
        }
        else {
          local_f4 = local_f4 & 0xffffff00 | (int)uVar3 >> 1;
        }
        local_f8 = local_f4;
        FUN_8025bdac(0,&local_f8);
        if (*(char *)(puVar4 + 0xd) == '\0') {
          dVar7 = (double)FLOAT_803dee20;
          dVar6 = (double)FLOAT_803dee38;
          uStack44 = (uint)*(ushort *)(puVar4 + 0xc);
          local_30 = 0x43300000;
          FUN_802470c8((double)((FLOAT_803dee3c *
                                FLOAT_803dee40 *
                                (float)((double)CONCAT44(0x43300000,uStack44) - DOUBLE_803dee30)) /
                               FLOAT_803dee44),auStack192,0x7a);
        }
        else {
          dVar7 = (double)FLOAT_803dee38;
          dVar6 = (double)FLOAT_803dee20;
          uStack44 = 0x8000 - *(ushort *)(puVar4 + 0xc) ^ 0x80000000;
          local_30 = 0x43300000;
          FUN_802470c8((double)((FLOAT_803dee3c *
                                FLOAT_803dee40 *
                                (float)((double)CONCAT44(0x43300000,uStack44) - DOUBLE_803dee50)) /
                               FLOAT_803dee44),auStack192,0x7a);
        }
        FUN_802472e4((double)FLOAT_803dee48,(double)FLOAT_803dee48,(double)FLOAT_803dee20,auStack240
                    );
        FUN_80246eb4(auStack192,auStack240,auStack192);
        FUN_802472e4((double)FLOAT_803dee24,(double)FLOAT_803dee24,(double)FLOAT_803dee20,auStack240
                    );
        FUN_80246eb4(auStack240,auStack192,auStack192);
        FUN_8025d160(auStack192,0x1e,1);
        FUN_8025889c(0x80,2,4);
        write_volatile_4(0xcc008000,*puVar4);
        write_volatile_4(0xcc008000,puVar4[1]);
        write_volatile_4(0xcc008000,puVar4[2]);
        write_volatile_4(0xcc008000,FLOAT_803dee20);
        write_volatile_4(0xcc008000,(float)dVar7);
        write_volatile_4(0xcc008000,puVar4[3]);
        write_volatile_4(0xcc008000,puVar4[4]);
        write_volatile_4(0xcc008000,puVar4[5]);
        write_volatile_4(0xcc008000,FLOAT_803dee38);
        write_volatile_4(0xcc008000,(float)dVar7);
        write_volatile_4(0xcc008000,puVar4[6]);
        write_volatile_4(0xcc008000,puVar4[7]);
        write_volatile_4(0xcc008000,puVar4[8]);
        write_volatile_4(0xcc008000,FLOAT_803dee38);
        write_volatile_4(0xcc008000,(float)dVar6);
        write_volatile_4(0xcc008000,puVar4[9]);
        write_volatile_4(0xcc008000,puVar4[10]);
        write_volatile_4(0xcc008000,puVar4[0xb]);
        write_volatile_4(0xcc008000,FLOAT_803dee20);
        write_volatile_4(0xcc008000,(float)dVar6);
      }
      puVar4 = puVar4 + 0xe;
      iVar1 = iVar1 + 1;
    } while (iVar1 < 0x100);
    FUN_8000f780();
  }
  __psq_l0(auStack8,uVar5);
  __psq_l1(auStack8,uVar5);
  __psq_l0(auStack24,uVar5);
  __psq_l1(auStack24,uVar5);
  return;
}

