// Function: FUN_8018f148
// Entry: 8018f148
// Size: 400 bytes

/* WARNING: Removing unreachable block (ram,0x8018f2b8) */

void FUN_8018f148(void)

{
  int iVar1;
  short sVar2;
  int iVar3;
  undefined4 uVar4;
  undefined8 in_f31;
  double dVar5;
  undefined8 uVar6;
  undefined auStack88 [12];
  float local_4c;
  float local_48;
  float local_44;
  undefined4 local_40;
  uint uStack60;
  undefined4 local_38;
  uint uStack52;
  undefined4 local_30;
  uint uStack44;
  undefined auStack8 [8];
  
  uVar4 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  uVar6 = FUN_802860d8();
  iVar1 = (int)((ulonglong)uVar6 >> 0x20);
  iVar3 = *(int *)(iVar1 + 0xb8);
  if (0 < (int)uVar6) {
    dVar5 = DOUBLE_803e3e60;
    for (sVar2 = 0; (int)sVar2 < (int)uVar6; sVar2 = sVar2 + 1) {
      uStack60 = FUN_800221a0(-(uint)*(ushort *)(iVar3 + 0x14));
      uStack60 = uStack60 ^ 0x80000000;
      local_40 = 0x43300000;
      local_4c = (float)((double)CONCAT44(0x43300000,uStack60) - dVar5);
      uStack52 = FUN_800221a0(-(uint)*(ushort *)(iVar3 + 0x18));
      uStack52 = uStack52 ^ 0x80000000;
      local_38 = 0x43300000;
      local_48 = (float)((double)CONCAT44(0x43300000,uStack52) - dVar5);
      uStack44 = FUN_800221a0(-(uint)*(ushort *)(iVar3 + 0x16));
      uStack44 = uStack44 ^ 0x80000000;
      local_30 = 0x43300000;
      local_44 = (float)((double)CONCAT44(0x43300000,uStack44) - dVar5);
      FUN_80021ac8(iVar3 + 0x1a,&local_4c);
      if ((*(char *)(iVar3 + 8) == '\x04') || (*(char *)(iVar3 + 8) == '\x06')) {
        local_4c = local_4c + *(float *)(iVar1 + 0xc);
        local_48 = local_48 + *(float *)(iVar1 + 0x10);
        local_44 = local_44 + *(float *)(iVar1 + 0x14);
        (**(code **)(*DAT_803dca88 + 8))
                  (iVar1,*(undefined2 *)(iVar3 + 10),auStack88,0x200001,0xffffffff,0);
      }
      else {
        (**(code **)(*DAT_803dca88 + 8))(iVar1,*(undefined2 *)(iVar3 + 10),auStack88,2,0xffffffff,0)
        ;
      }
    }
  }
  __psq_l0(auStack8,uVar4);
  __psq_l1(auStack8,uVar4);
  FUN_80286124();
  return;
}

