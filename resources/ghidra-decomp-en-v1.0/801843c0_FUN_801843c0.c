// Function: FUN_801843c0
// Entry: 801843c0
// Size: 572 bytes

void FUN_801843c0(void)

{
  int iVar1;
  byte bVar3;
  undefined4 uVar2;
  int iVar4;
  int iVar5;
  undefined auStack264 [24];
  undefined4 local_f0;
  undefined4 local_ec;
  undefined4 local_e8;
  undefined4 local_c0 [12];
  undefined4 local_90 [16];
  float local_50 [4];
  undefined local_40 [4];
  undefined local_3c;
  int local_34 [13];
  
  iVar1 = FUN_802860dc();
  iVar5 = *(int *)(iVar1 + 0x54);
  if (iVar5 == 0) {
    uVar2 = 0;
  }
  else {
    local_c0[0] = *(undefined4 *)(iVar1 + 0xc);
    local_c0[1] = *(undefined4 *)(iVar1 + 0x10);
    local_c0[2] = *(undefined4 *)(iVar1 + 0x14);
    local_f0 = *(undefined4 *)(iVar1 + 0x80);
    local_ec = *(undefined4 *)(iVar1 + 0x84);
    local_e8 = *(undefined4 *)(iVar1 + 0x88);
    local_50[0] = FLOAT_803e39f4;
    local_40[0] = 0xff;
    local_3c = 3;
    FUN_8006961c(auStack264,&local_f0,local_c0,local_50,1);
    FUN_800691c0(iVar1,auStack264,*(undefined2 *)(iVar5 + 0xb2),1);
    bVar3 = FUN_80067958(iVar1,&local_f0,local_c0,1,local_90,0);
    if (bVar3 == 0) {
      uVar2 = 0;
    }
    else {
      if ((bVar3 & 1) == 0) {
        if ((bVar3 & 2) == 0) {
          if ((bVar3 & 4) == 0) {
            iVar4 = 3;
          }
          else {
            iVar4 = 2;
          }
        }
        else {
          iVar4 = 1;
        }
      }
      else {
        iVar4 = 0;
      }
      *(undefined *)(iVar5 + 0xac) = local_40[iVar4];
      *(undefined4 *)(iVar5 + 0x3c) = local_c0[iVar4 * 3];
      *(undefined4 *)(iVar5 + 0x40) = local_c0[iVar4 * 3 + 1];
      *(undefined4 *)(iVar5 + 0x44) = local_c0[iVar4 * 3 + 2];
      DAT_803ac7a0 = local_90[iVar4 * 4];
      DAT_803ac7a4 = local_90[iVar4 * 4 + 1];
      DAT_803ac7a8 = local_90[iVar4 * 4 + 2];
      DAT_803ac7ac = local_90[iVar4 * 4 + 3];
      if (local_34[iVar4] == 0) {
        *(byte *)(iVar5 + 0xad) = *(byte *)(iVar5 + 0xad) | 1;
        *(undefined4 *)(iVar1 + 0xc) = *(undefined4 *)(iVar5 + 0x3c);
        *(undefined4 *)(iVar1 + 0x10) = *(undefined4 *)(iVar5 + 0x40);
        *(undefined4 *)(iVar1 + 0x14) = *(undefined4 *)(iVar5 + 0x44);
        *(undefined4 *)(iVar5 + 0x10) = *(undefined4 *)(iVar1 + 0x80);
        *(undefined4 *)(iVar5 + 0x14) = *(undefined4 *)(iVar1 + 0x84);
        *(undefined4 *)(iVar5 + 0x18) = *(undefined4 *)(iVar1 + 0x88);
        uVar2 = 1;
      }
      else {
        *(byte *)(iVar5 + 0xad) = *(byte *)(iVar5 + 0xad) | 2;
        *(undefined4 *)(iVar1 + 0xc) = *(undefined4 *)(iVar5 + 0x3c);
        *(undefined4 *)(iVar1 + 0x10) = *(undefined4 *)(iVar5 + 0x40);
        *(undefined4 *)(iVar1 + 0x14) = *(undefined4 *)(iVar5 + 0x44);
        *(undefined4 *)(iVar5 + 0x10) = *(undefined4 *)(iVar1 + 0x80);
        *(undefined4 *)(iVar5 + 0x14) = *(undefined4 *)(iVar1 + 0x84);
        *(undefined4 *)(iVar5 + 0x18) = *(undefined4 *)(iVar1 + 0x88);
        uVar2 = 1;
      }
    }
  }
  FUN_80286128(uVar2);
  return;
}

