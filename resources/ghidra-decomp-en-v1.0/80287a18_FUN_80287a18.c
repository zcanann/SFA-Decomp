// Function: FUN_80287a18
// Entry: 80287a18
// Size: 696 bytes

/* WARNING: Removing unreachable block (ram,0x80287a7c) */

int FUN_80287a18(void)

{
  bool bVar1;
  int iVar2;
  int iVar3;
  uint uVar4;
  int iVar5;
  byte local_18 [12];
  
  iVar5 = 0;
  iVar3 = FUN_8028cf9c(local_18);
  do {
    iVar2 = DAT_803d82d8;
    if ((iVar3 != 0) || (iVar5 != 0)) {
      return -1;
    }
    if (DAT_803d82dc != 2) {
      DAT_803d82e0 = 0;
    }
    if (DAT_803d82dc == 2) {
LAB_80287ad4:
      if (local_18[0] == 0x7e) {
        if (DAT_803d82e0 == 0) {
          if (*(uint *)(DAT_803d82d8 + 8) < 2) {
            FUN_8028a584(DAT_803d82d8,0xff,2);
            if (DAT_803d82d4 != -1) {
              FUN_80287738();
              DAT_803d82d4 = -1;
            }
            bVar1 = false;
            DAT_803d82d8 = 0;
          }
          else {
            bVar1 = true;
            *(undefined4 *)(DAT_803d82d8 + 0xc) = 0;
            *(int *)(iVar2 + 8) = *(int *)(iVar2 + 8) + -1;
          }
          if (bVar1) {
            iVar5 = DAT_803d82d4;
            DAT_803d82d4 = 0xffffffff;
            DAT_803d82d8 = 0;
            DAT_803d82dc = 0;
            return iVar5;
          }
          DAT_803d82dc = 0;
        }
        else {
          FUN_8028a584(DAT_803d82d8,0xff,4);
          if (DAT_803d82d4 != -1) {
            FUN_80287738();
            DAT_803d82d4 = -1;
          }
          DAT_803d82d8 = 0;
          DAT_803d82dc = 0;
        }
      }
      else {
        if (DAT_803d82e0 == 0) {
          if (local_18[0] == 0x7d) {
            DAT_803d82e0 = 1;
            goto LAB_80287c98;
          }
        }
        else {
          local_18[0] = local_18[0] ^ 0x20;
          DAT_803d82e0 = 0;
        }
        uVar4 = *(uint *)(DAT_803d82d8 + 0xc);
        if (uVar4 < 0x880) {
          *(uint *)(DAT_803d82d8 + 0xc) = uVar4 + 1;
          iVar5 = 0;
          *(byte *)(iVar2 + uVar4 + 0x10) = local_18[0];
          *(int *)(iVar2 + 8) = *(int *)(iVar2 + 8) + 1;
        }
        else {
          iVar5 = 0x301;
        }
        DAT_803d82e4 = DAT_803d82e4 + local_18[0];
      }
    }
    else if (DAT_803d82dc < 2) {
      if (DAT_803d82dc == 0) {
        if (local_18[0] == 0x7e) {
          iVar5 = FUN_802877c8(&DAT_803d82d4,&DAT_803d82d8);
          DAT_803d82e4 = '\0';
          DAT_803d82dc = 1;
        }
      }
      else if (local_18[0] != 0x7e) {
        DAT_803d82dc = 2;
        goto LAB_80287ad4;
      }
    }
    else if ((DAT_803d82dc < 4) && (local_18[0] == 0x7e)) {
      if (DAT_803d82d4 != -1) {
        FUN_80287738();
        DAT_803d82d4 = -1;
      }
      DAT_803d82d8 = 0;
      DAT_803d82dc = 0;
    }
LAB_80287c98:
    iVar3 = FUN_8028cf9c(local_18);
  } while( true );
}

