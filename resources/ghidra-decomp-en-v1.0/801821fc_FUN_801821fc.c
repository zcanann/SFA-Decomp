// Function: FUN_801821fc
// Entry: 801821fc
// Size: 776 bytes

void FUN_801821fc(void)

{
  float fVar1;
  int iVar2;
  int iVar3;
  undefined4 uVar4;
  byte bVar5;
  int iVar6;
  undefined auStack272 [24];
  undefined4 local_f8;
  undefined4 local_f4;
  undefined4 local_f0;
  undefined4 local_c8 [12];
  undefined4 local_98 [16];
  float local_58 [4];
  undefined local_48 [4];
  undefined local_44;
  int local_3c [5];
  undefined4 local_28;
  uint uStack36;
  
  iVar2 = FUN_802860dc();
  iVar6 = *(int *)(iVar2 + 0x54);
  iVar3 = FUN_800640cc((double)FLOAT_803e3970,iVar2 + 0x80,iVar2 + 0xc,1,0,iVar2,1,0xffffffff,0xff,0
                      );
  if (iVar3 == 0) {
    if ((*(uint *)(iVar6 + 0x48) >> 4 == 0) || (*(char *)(iVar6 + 0x70) != '\0')) {
      uVar4 = 0;
    }
    else {
      local_c8[0] = *(undefined4 *)(iVar2 + 0xc);
      local_c8[1] = *(undefined4 *)(iVar2 + 0x10);
      local_c8[2] = *(undefined4 *)(iVar2 + 0x14);
      local_f8 = *(undefined4 *)(iVar2 + 0x80);
      local_f4 = *(undefined4 *)(iVar2 + 0x84);
      local_f0 = *(undefined4 *)(iVar2 + 0x88);
      uStack36 = (int)*(short *)(iVar6 + 0x5a) ^ 0x80000000;
      local_28 = 0x43300000;
      local_58[0] = (float)((double)CONCAT44(0x43300000,uStack36) - DOUBLE_803e3968);
      local_48[0] = 0xff;
      local_44 = 3;
      FUN_8006961c(auStack272,&local_f8,local_c8,local_58,1);
      FUN_800691c0(iVar2,auStack272,*(undefined2 *)(iVar6 + 0xb2),1);
      bVar5 = FUN_80067958(iVar2,&local_f8,local_c8,1,local_98,0);
      if (bVar5 == 0) {
        uVar4 = 0;
      }
      else {
        if ((bVar5 & 1) == 0) {
          if ((bVar5 & 2) == 0) {
            if ((bVar5 & 4) == 0) {
              iVar3 = 3;
            }
            else {
              iVar3 = 2;
            }
          }
          else {
            iVar3 = 1;
          }
        }
        else {
          iVar3 = 0;
        }
        *(undefined *)(iVar6 + 0xac) = local_48[iVar3];
        *(undefined4 *)(iVar6 + 0x3c) = local_c8[iVar3 * 3];
        *(undefined4 *)(iVar6 + 0x40) = local_c8[iVar3 * 3 + 1];
        *(undefined4 *)(iVar6 + 0x44) = local_c8[iVar3 * 3 + 2];
        DAT_803ac790 = local_98[iVar3 * 4];
        DAT_803ac794 = local_98[iVar3 * 4 + 1];
        DAT_803ac798 = local_98[iVar3 * 4 + 2];
        DAT_803ac79c = local_98[iVar3 * 4 + 3];
        if (local_3c[iVar3] == 0) {
          *(byte *)(iVar6 + 0xad) = *(byte *)(iVar6 + 0xad) | 1;
          *(undefined4 *)(iVar2 + 0xc) = *(undefined4 *)(iVar6 + 0x3c);
          *(undefined4 *)(iVar2 + 0x10) = *(undefined4 *)(iVar6 + 0x40);
          *(undefined4 *)(iVar2 + 0x14) = *(undefined4 *)(iVar6 + 0x44);
          *(undefined4 *)(iVar6 + 0x10) = *(undefined4 *)(iVar2 + 0x80);
          *(undefined4 *)(iVar6 + 0x14) = *(undefined4 *)(iVar2 + 0x84);
          *(undefined4 *)(iVar6 + 0x18) = *(undefined4 *)(iVar2 + 0x88);
          fVar1 = FLOAT_803e3938;
          *(float *)(iVar2 + 0x24) = FLOAT_803e3938;
          *(float *)(iVar2 + 0x28) = fVar1;
          *(float *)(iVar2 + 0x2c) = fVar1;
          uVar4 = 1;
        }
        else {
          *(byte *)(iVar6 + 0xad) = *(byte *)(iVar6 + 0xad) | 2;
          *(undefined4 *)(iVar2 + 0xc) = *(undefined4 *)(iVar6 + 0x3c);
          *(undefined4 *)(iVar2 + 0x10) = *(undefined4 *)(iVar6 + 0x40);
          *(undefined4 *)(iVar2 + 0x14) = *(undefined4 *)(iVar6 + 0x44);
          *(undefined4 *)(iVar6 + 0x10) = *(undefined4 *)(iVar2 + 0x80);
          *(undefined4 *)(iVar6 + 0x14) = *(undefined4 *)(iVar2 + 0x84);
          *(undefined4 *)(iVar6 + 0x18) = *(undefined4 *)(iVar2 + 0x88);
          fVar1 = FLOAT_803e3938;
          *(float *)(iVar2 + 0x24) = FLOAT_803e3938;
          *(float *)(iVar2 + 0x28) = fVar1;
          *(float *)(iVar2 + 0x2c) = fVar1;
          uVar4 = 1;
        }
      }
    }
  }
  else {
    *(byte *)(iVar6 + 0xad) = *(byte *)(iVar6 + 0xad) | 1;
    *(undefined4 *)(iVar6 + 0x10) = *(undefined4 *)(iVar2 + 0x80);
    *(undefined4 *)(iVar6 + 0x14) = *(undefined4 *)(iVar2 + 0x84);
    *(undefined4 *)(iVar6 + 0x18) = *(undefined4 *)(iVar2 + 0x88);
    fVar1 = FLOAT_803e3938;
    *(float *)(iVar2 + 0x24) = FLOAT_803e3938;
    *(float *)(iVar2 + 0x28) = fVar1;
    *(float *)(iVar2 + 0x2c) = fVar1;
    uVar4 = 1;
  }
  FUN_80286128(uVar4);
  return;
}

