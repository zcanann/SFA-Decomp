// Function: FUN_80184918
// Entry: 80184918
// Size: 572 bytes

void FUN_80184918(void)

{
  int iVar1;
  byte bVar2;
  int iVar3;
  int iVar4;
  uint auStack_108 [6];
  float local_f0;
  undefined4 local_ec;
  undefined4 local_e8;
  float local_c0 [12];
  undefined4 local_90 [16];
  float local_50 [4];
  undefined local_40 [4];
  undefined local_3c;
  int local_34 [13];
  
  iVar1 = FUN_80286840();
  iVar4 = *(int *)(iVar1 + 0x54);
  if (iVar4 != 0) {
    local_c0[0] = *(float *)(iVar1 + 0xc);
    local_c0[1] = *(float *)(iVar1 + 0x10);
    local_c0[2] = *(float *)(iVar1 + 0x14);
    local_f0 = *(float *)(iVar1 + 0x80);
    local_ec = *(undefined4 *)(iVar1 + 0x84);
    local_e8 = *(undefined4 *)(iVar1 + 0x88);
    local_50[0] = FLOAT_803e468c;
    local_40[0] = 0xff;
    local_3c = 3;
    FUN_80069798(auStack_108,&local_f0,local_c0,local_50,1);
    FUN_8006933c(iVar1,auStack_108,(uint)*(ushort *)(iVar4 + 0xb2),'\x01');
    bVar2 = FUN_80067ad4();
    if (bVar2 != 0) {
      if ((bVar2 & 1) == 0) {
        if ((bVar2 & 2) == 0) {
          if ((bVar2 & 4) == 0) {
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
      *(undefined *)(iVar4 + 0xac) = local_40[iVar3];
      *(float *)(iVar4 + 0x3c) = local_c0[iVar3 * 3];
      *(float *)(iVar4 + 0x40) = local_c0[iVar3 * 3 + 1];
      *(float *)(iVar4 + 0x44) = local_c0[iVar3 * 3 + 2];
      DAT_803ad400 = local_90[iVar3 * 4];
      DAT_803ad404 = local_90[iVar3 * 4 + 1];
      DAT_803ad408 = local_90[iVar3 * 4 + 2];
      DAT_803ad40c = local_90[iVar3 * 4 + 3];
      if (local_34[iVar3] == 0) {
        *(byte *)(iVar4 + 0xad) = *(byte *)(iVar4 + 0xad) | 1;
        *(undefined4 *)(iVar1 + 0xc) = *(undefined4 *)(iVar4 + 0x3c);
        *(undefined4 *)(iVar1 + 0x10) = *(undefined4 *)(iVar4 + 0x40);
        *(undefined4 *)(iVar1 + 0x14) = *(undefined4 *)(iVar4 + 0x44);
        *(undefined4 *)(iVar4 + 0x10) = *(undefined4 *)(iVar1 + 0x80);
        *(undefined4 *)(iVar4 + 0x14) = *(undefined4 *)(iVar1 + 0x84);
        *(undefined4 *)(iVar4 + 0x18) = *(undefined4 *)(iVar1 + 0x88);
      }
      else {
        *(byte *)(iVar4 + 0xad) = *(byte *)(iVar4 + 0xad) | 2;
        *(undefined4 *)(iVar1 + 0xc) = *(undefined4 *)(iVar4 + 0x3c);
        *(undefined4 *)(iVar1 + 0x10) = *(undefined4 *)(iVar4 + 0x40);
        *(undefined4 *)(iVar1 + 0x14) = *(undefined4 *)(iVar4 + 0x44);
        *(undefined4 *)(iVar4 + 0x10) = *(undefined4 *)(iVar1 + 0x80);
        *(undefined4 *)(iVar4 + 0x14) = *(undefined4 *)(iVar1 + 0x84);
        *(undefined4 *)(iVar4 + 0x18) = *(undefined4 *)(iVar1 + 0x88);
      }
    }
  }
  FUN_8028688c();
  return;
}

