// Function: FUN_8028817c
// Entry: 8028817c
// Size: 696 bytes

/* WARNING: Removing unreachable block (ram,0x802881e0) */

int FUN_8028817c(void)

{
  bool bVar1;
  int iVar2;
  int iVar3;
  uint uVar4;
  int iVar5;
  byte local_18 [12];
  
  iVar5 = 0;
  iVar3 = FUN_8028d6fc(local_18);
  do {
    iVar2 = DAT_803d8f38;
    if ((iVar3 != 0) || (iVar5 != 0)) {
      return -1;
    }
    if (DAT_803d8f3c != 2) {
      DAT_803d8f40 = 0;
    }
    if (DAT_803d8f3c == 2) {
LAB_80288238:
      if (local_18[0] == 0x7e) {
        if (DAT_803d8f40 == 0) {
          if (*(uint *)(DAT_803d8f38 + 8) < 2) {
            FUN_8028ace8(DAT_803d8f38,0xff,2);
            if (DAT_803d8f34 != -1) {
              FUN_80287e9c(DAT_803d8f34);
              DAT_803d8f34 = -1;
            }
            bVar1 = false;
            DAT_803d8f38 = 0;
          }
          else {
            bVar1 = true;
            *(undefined4 *)(DAT_803d8f38 + 0xc) = 0;
            *(int *)(iVar2 + 8) = *(int *)(iVar2 + 8) + -1;
          }
          if (bVar1) {
            iVar5 = DAT_803d8f34;
            DAT_803d8f34 = 0xffffffff;
            DAT_803d8f38 = 0;
            DAT_803d8f3c = 0;
            return iVar5;
          }
          DAT_803d8f3c = 0;
        }
        else {
          FUN_8028ace8(DAT_803d8f38,0xff,4);
          if (DAT_803d8f34 != -1) {
            FUN_80287e9c(DAT_803d8f34);
            DAT_803d8f34 = -1;
          }
          DAT_803d8f38 = 0;
          DAT_803d8f3c = 0;
        }
      }
      else {
        if (DAT_803d8f40 == 0) {
          if (local_18[0] == 0x7d) {
            DAT_803d8f40 = 1;
            goto LAB_802883fc;
          }
        }
        else {
          local_18[0] = local_18[0] ^ 0x20;
          DAT_803d8f40 = 0;
        }
        uVar4 = *(uint *)(DAT_803d8f38 + 0xc);
        if (uVar4 < 0x880) {
          *(uint *)(DAT_803d8f38 + 0xc) = uVar4 + 1;
          iVar5 = 0;
          *(byte *)(iVar2 + uVar4 + 0x10) = local_18[0];
          *(int *)(iVar2 + 8) = *(int *)(iVar2 + 8) + 1;
        }
        else {
          iVar5 = 0x301;
        }
        DAT_803d8f44 = DAT_803d8f44 + local_18[0];
      }
    }
    else if (DAT_803d8f3c < 2) {
      if (DAT_803d8f3c == 0) {
        if (local_18[0] == 0x7e) {
          iVar5 = FUN_80287f2c(&DAT_803d8f34,&DAT_803d8f38);
          DAT_803d8f44 = '\0';
          DAT_803d8f3c = 1;
        }
      }
      else if (local_18[0] != 0x7e) {
        DAT_803d8f3c = 2;
        goto LAB_80288238;
      }
    }
    else if ((DAT_803d8f3c < 4) && (local_18[0] == 0x7e)) {
      if (DAT_803d8f34 != -1) {
        FUN_80287e9c(DAT_803d8f34);
        DAT_803d8f34 = -1;
      }
      DAT_803d8f38 = 0;
      DAT_803d8f3c = 0;
    }
LAB_802883fc:
    iVar3 = FUN_8028d6fc(local_18);
  } while( true );
}

